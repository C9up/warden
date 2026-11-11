/**
 * MfaManager — orchestrates the stateful "enable 2FA" lifecycle for a user:
 * TOTP enrollment (pending → confirmed) and single-use backup codes, over a
 * pluggable factor store (in-memory default).
 *
 * OTP (email/SMS) and WebAuthn are NOT folded in here: OTP is ephemeral
 * (challenge/response, no enrollment) and WebAuthn already persists its own
 * passkeys in its credential store. Use `OtpProvider` / `WebauthnProvider`
 * directly for those, alongside this manager.
 */

import { randomBytes } from "node:crypto";
import type { AttemptStore } from "../AttemptStore.js";
import { AuthRateLimiter } from "../AuthRateLimiter.js";
import { WardenError } from "../errors.js";
import type { BackupCodesProvider } from "./BackupCodesProvider.js";
import type { TotpProvider } from "./TotpProvider.js";

export type MfaFactorKind = "totp" | "backup_codes";

export interface MfaFactor {
	id: string;
	userId: string;
	kind: MfaFactorKind;
	label?: string;
	/** TOTP shared secret (base32), present for `totp` factors. */
	secret?: string;
	/** Salted hashes of the remaining backup codes, for `backup_codes` factors. */
	backupHashes?: string[];
	/** Epoch ms when the factor became usable; absent while pending. */
	confirmedAt?: number;
	createdAt: number;
}

/** Public, secret-free view of an enrolled factor. */
export interface MfaFactorSummary {
	id: string;
	kind: MfaFactorKind;
	label?: string;
	confirmed: boolean;
}

export interface MfaFactorStore {
	save(factor: MfaFactor): Promise<void>;
	findById(id: string): Promise<MfaFactor | null>;
	findByUser(userId: string): Promise<MfaFactor[]>;
	delete(id: string): Promise<void>;
	/**
	 * Remove `hash` from the factor's backup hashes — ATOMICALLY, and only if
	 * it is still there (an `UPDATE … WHERE` on the hash, or a Redis `SREM`).
	 * True when this call removed it: the code is accepted, once. A read, a
	 * filter and a save let two requests with the same code both succeed.
	 */
	consumeBackupHash(factorId: string, hash: string): Promise<boolean>;
}

export class MemoryMfaFactorStore implements MfaFactorStore {
	#store = new Map<string, MfaFactor>();
	async save(factor: MfaFactor): Promise<void> {
		this.#store.set(factor.id, factor);
	}
	async findById(id: string): Promise<MfaFactor | null> {
		return this.#store.get(id) ?? null;
	}
	async findByUser(userId: string): Promise<MfaFactor[]> {
		return [...this.#store.values()].filter((f) => f.userId === userId);
	}
	async delete(id: string): Promise<void> {
		this.#store.delete(id);
	}
	/** Synchronous between read and write: nothing interleaves. */
	async consumeBackupHash(factorId: string, hash: string): Promise<boolean> {
		const factor = this.#store.get(factorId);
		const hashes = factor?.backupHashes;
		if (
			factor === undefined ||
			hashes === undefined ||
			!hashes.includes(hash)
		) {
			return false;
		}
		this.#store.set(factorId, {
			...factor,
			backupHashes: hashes.filter((stored) => stored !== hash),
		});
		return true;
	}
}

export interface MfaRateLimitConfig {
	/** Verifications allowed per user before lockout. Default `5`. */
	maxAttempts?: number;
	/** Lockout / counter window in seconds. Default `900` (15 min). */
	windowSeconds?: number;
	/**
	 * Where the counts live. Default: this process's memory. A cluster passes a
	 * shared one (`RedisAttemptStore`), or a lockout holds only on the instance
	 * that counted it.
	 */
	store?: AttemptStore;
}

export interface MfaManagerConfig {
	/** App/brand name shown in the authenticator (the TOTP issuer). */
	issuer: string;
	totp?: TotpProvider;
	backupCodes?: BackupCodesProvider;
	store?: MfaFactorStore;
	/**
	 * Per-user brute-force protection on `verify()`, `verifyTotp()`,
	 * `verifyBackupCode()` and `confirmTotp()`, one shared count. Defaults to
	 * 5 / 15 min.
	 */
	rateLimit?: MfaRateLimitConfig;
}

export class MfaManager {
	readonly #issuer: string;
	readonly #totp?: TotpProvider;
	readonly #backupCodes?: BackupCodesProvider;
	readonly #store: MfaFactorStore;
	readonly #limiter: AuthRateLimiter;

	constructor(config: MfaManagerConfig) {
		if (!config?.issuer) {
			throw new WardenError("INVALID_CONFIG", "MfaManager requires an issuer");
		}
		this.#issuer = config.issuer;
		this.#totp = config.totp;
		this.#backupCodes = config.backupCodes;
		this.#store = config.store ?? new MemoryMfaFactorStore();
		this.#limiter = new AuthRateLimiter({
			maxAttempts: config.rateLimit?.maxAttempts ?? 5,
			windowSeconds: config.rateLimit?.windowSeconds ?? 900,
			store: config.rateLimit?.store,
		});
	}

	// ── TOTP enrollment ──────────────────────────────────────────────

	/**
	 * Begin TOTP enrollment: persist a pending factor and return the secret +
	 * `otpauth://` URI to show as a QR code. The factor is unusable until
	 * `confirmTotp()` succeeds.
	 */
	async enrollTotp(
		user: { id: string; name: string },
		label?: string,
	): Promise<{ factorId: string; secret: string; uri: string }> {
		const totp = this.#requireTotp();
		const { secret, uri } = totp.enroll(user.name, this.#issuer);
		const factor: MfaFactor = {
			id: newId(),
			userId: user.id,
			kind: "totp",
			label,
			secret,
			createdAt: Date.now(),
		};
		await this.#store.save(factor);
		return { factorId: factor.id, secret, uri };
	}

	/**
	 * Confirm a pending TOTP factor of `userId` by verifying a first code.
	 *
	 * Takes the owner beside the factor id and refuses a factor that belongs
	 * to someone else: a factor id is something an application passes through
	 * a request, and one leaked through a log or a support tool must not let
	 * another account act on it. The attempt counts against the same lockout
	 * as {@link verify}, so the first code cannot be guessed without limit.
	 */
	async confirmTotp(
		userId: string,
		factorId: string,
		code: string,
	): Promise<boolean> {
		const totp = this.#requireTotp();
		const key = lockoutKey(userId);
		if (!(await this.#limiter.attempt(key)).allowed) {
			return false;
		}
		const factor = await this.#ownedFactor(userId, factorId);
		if (factor?.kind !== "totp" || !factor.secret) {
			return false;
		}
		if (!(await totp.verify(factor.secret, code))) {
			return false;
		}
		await this.#store.save({ ...factor, confirmedAt: Date.now() });
		await this.#limiter.clear(key);
		return true;
	}

	/**
	 * Verify a TOTP code against the user's confirmed authenticator factors.
	 *
	 * Counts against the same per-user lockout as {@link verify}: an app
	 * calling this directly (to tell the factors apart in its UI) must not get
	 * unlimited guesses at a six-digit code.
	 */
	async verifyTotp(userId: string, code: string): Promise<boolean> {
		const totp = this.#requireTotp();
		return this.#limited(userId, () => this.#checkTotp(totp, userId, code));
	}

	async #checkTotp(
		totp: TotpProvider,
		userId: string,
		code: string,
	): Promise<boolean> {
		const factors = await this.#store.findByUser(userId);
		// Sequential, not Promise.all: the replay guard must see one accepted
		// code at a time, and stopping at the first match avoids burning the
		// code against a second factor that would then reject it as replayed.
		for (const factor of factors) {
			if (
				factor.kind !== "totp" ||
				factor.confirmedAt === undefined ||
				factor.secret === undefined
			) {
				continue;
			}
			if (await totp.verify(factor.secret, code)) return true;
		}
		return false;
	}

	// ── Backup codes ─────────────────────────────────────────────────

	/**
	 * Generate (or regenerate) the user's backup codes. Returns the plaintext
	 * codes to display ONCE; only hashes are stored. Any prior backup-code
	 * factor is replaced.
	 */
	async createBackupCodes(userId: string, label?: string): Promise<string[]> {
		const provider = this.#requireBackupCodes();
		const existing = await this.#store.findByUser(userId);
		for (const f of existing) {
			if (f.kind === "backup_codes") {
				await this.#store.delete(f.id);
			}
		}
		const { codes, hashes } = provider.generate();
		await this.#store.save({
			id: newId(),
			userId,
			kind: "backup_codes",
			label,
			backupHashes: hashes,
			// Backup codes are usable as soon as they are shown.
			confirmedAt: Date.now(),
			createdAt: Date.now(),
		});
		return codes;
	}

	/**
	 * Verify and consume one backup code for the user. Counts against the same
	 * per-user lockout as {@link verify}.
	 */
	async verifyBackupCode(userId: string, code: string): Promise<boolean> {
		const provider = this.#requireBackupCodes();
		return this.#limited(userId, () =>
			this.#checkBackupCode(provider, userId, code),
		);
	}

	async #checkBackupCode(
		provider: BackupCodesProvider,
		userId: string,
		code: string,
	): Promise<boolean> {
		const factors = await this.#store.findByUser(userId);
		for (const factor of factors) {
			if (factor.kind !== "backup_codes" || !factor.backupHashes) {
				continue;
			}
			const result = provider.verify(factor.backupHashes, code);
			// Only the request that removes the hash wins; one that verified the
			// same code a moment later finds it gone.
			if (
				result.matched !== undefined &&
				(await this.#store.consumeBackupHash(factor.id, result.matched))
			) {
				return true;
			}
		}
		return false;
	}

	// ── Unified verify + status ──────────────────────────────────────

	/**
	 * Verify a code entered in a single "2FA code" field: tries the user's TOTP
	 * factors first, then falls back to consuming a backup code.
	 */
	async verify(userId: string, code: string): Promise<boolean> {
		// One attempt for the code, whichever factor ends up answering it.
		return this.#limited(userId, async () => {
			const totp = this.#totp;
			if (totp && (await this.#checkTotp(totp, userId, code))) return true;
			const backupCodes = this.#backupCodes;
			return (
				backupCodes !== undefined &&
				(await this.#checkBackupCode(backupCodes, userId, code))
			);
		});
	}

	/**
	 * Run one code check under the per-user lockout.
	 *
	 * Counted BEFORE the code is checked, by one atomic increment: reading
	 * "not locked" first and counting the failure after let a burst of
	 * concurrent attempts all reach the providers. A success clears the count.
	 */
	async #limited(
		userId: string,
		check: () => Promise<boolean>,
	): Promise<boolean> {
		const key = lockoutKey(userId);
		if (!(await this.#limiter.attempt(key)).allowed) {
			return false;
		}
		const ok = await check();
		if (ok) await this.#limiter.clear(key);
		return ok;
	}

	/**
	 * Whether the user is currently locked out of the code checks after too many
	 * failed attempts. Use it to surface a "try again later" message.
	 */
	isLocked(userId: string): Promise<boolean> {
		return this.#limiter.isBlocked(lockoutKey(userId));
	}

	/** List the user's factors without exposing any secret material. */
	async listFactors(userId: string): Promise<MfaFactorSummary[]> {
		const factors = await this.#store.findByUser(userId);
		return factors.map((f) => ({
			id: f.id,
			kind: f.kind,
			label: f.label,
			confirmed: f.confirmedAt !== undefined,
		}));
	}

	/** Whether the user has at least one confirmed factor. */
	async isEnabled(userId: string): Promise<boolean> {
		const factors = await this.#store.findByUser(userId);
		return factors.some((f) => f.confirmedAt !== undefined);
	}

	/**
	 * Remove one of `userId`'s factors (e.g. the user disables their
	 * authenticator). Answers whether a factor was removed: `false` for an
	 * unknown id or one owned by another user, which is left in place.
	 */
	async disableFactor(userId: string, factorId: string): Promise<boolean> {
		const factor = await this.#ownedFactor(userId, factorId);
		if (factor === null) return false;
		await this.#store.delete(factor.id);
		return true;
	}

	/** The factor, only when it belongs to `userId`. */
	async #ownedFactor(
		userId: string,
		factorId: string,
	): Promise<MfaFactor | null> {
		const factor = await this.#store.findById(factorId);
		return factor !== null && factor.userId === userId ? factor : null;
	}

	#requireTotp(): TotpProvider {
		if (!this.#totp) {
			throw new WardenError(
				"INVALID_CONFIG",
				"MfaManager has no TotpProvider configured",
			);
		}
		return this.#totp;
	}

	#requireBackupCodes(): BackupCodesProvider {
		if (!this.#backupCodes) {
			throw new WardenError(
				"INVALID_CONFIG",
				"MfaManager has no BackupCodesProvider configured",
			);
		}
		return this.#backupCodes;
	}
}

/** The limiter key of a user's MFA attempts. */
function lockoutKey(userId: string): string {
	return `mfa:${userId}`;
}

function newId(): string {
	return randomBytes(16).toString("hex");
}
