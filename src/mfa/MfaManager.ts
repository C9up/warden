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
}

export interface MfaRateLimitConfig {
	/** Failed verifications allowed per user before lockout. Default `5`. */
	maxAttempts?: number;
	/** Lockout / counter window in seconds. Default `900` (15 min). */
	windowSeconds?: number;
}

export interface MfaManagerConfig {
	/** App/brand name shown in the authenticator (the TOTP issuer). */
	issuer: string;
	totp?: TotpProvider;
	backupCodes?: BackupCodesProvider;
	store?: MfaFactorStore;
	/** Per-user brute-force protection on `verify()`. Defaults to 5 / 15 min. */
	rateLimit?: MfaRateLimitConfig;
}

interface AttemptEntry {
	count: number;
	resetAt: number;
}

export class MfaManager {
	readonly #issuer: string;
	readonly #totp?: TotpProvider;
	readonly #backupCodes?: BackupCodesProvider;
	readonly #store: MfaFactorStore;
	readonly #maxAttempts: number;
	readonly #windowMs: number;
	readonly #attempts = new Map<string, AttemptEntry>();

	constructor(config: MfaManagerConfig) {
		if (!config?.issuer) {
			throw new WardenError("INVALID_CONFIG", "MfaManager requires an issuer");
		}
		this.#issuer = config.issuer;
		this.#totp = config.totp;
		this.#backupCodes = config.backupCodes;
		this.#store = config.store ?? new MemoryMfaFactorStore();
		this.#maxAttempts = config.rateLimit?.maxAttempts ?? 5;
		this.#windowMs = (config.rateLimit?.windowSeconds ?? 900) * 1000;
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

	/** Confirm a pending TOTP factor by verifying a first code. */
	async confirmTotp(factorId: string, code: string): Promise<boolean> {
		const totp = this.#requireTotp();
		const factor = await this.#store.findById(factorId);
		if (!factor || factor.kind !== "totp" || !factor.secret) {
			return false;
		}
		if (!totp.verify(factor.secret, code)) {
			return false;
		}
		await this.#store.save({ ...factor, confirmedAt: Date.now() });
		return true;
	}

	/** Verify a TOTP code against the user's confirmed authenticator factors. */
	async verifyTotp(userId: string, code: string): Promise<boolean> {
		const totp = this.#requireTotp();
		const factors = await this.#store.findByUser(userId);
		return factors.some(
			(f) =>
				f.kind === "totp" &&
				f.confirmedAt !== undefined &&
				f.secret !== undefined &&
				totp.verify(f.secret, code),
		);
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

	/** Verify and consume one backup code for the user. */
	async verifyBackupCode(userId: string, code: string): Promise<boolean> {
		const provider = this.#requireBackupCodes();
		const factors = await this.#store.findByUser(userId);
		for (const factor of factors) {
			if (factor.kind !== "backup_codes" || !factor.backupHashes) {
				continue;
			}
			const result = provider.verify(factor.backupHashes, code);
			if (result.ok) {
				await this.#store.save({ ...factor, backupHashes: result.remaining });
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
		if (this.#isLocked(userId)) {
			return false;
		}
		let ok = false;
		if (this.#totp && (await this.verifyTotp(userId, code))) {
			ok = true;
		} else if (
			this.#backupCodes &&
			(await this.verifyBackupCode(userId, code))
		) {
			ok = true;
		}
		if (ok) {
			this.#attempts.delete(userId);
		} else {
			this.#recordFailure(userId);
		}
		return ok;
	}

	/**
	 * Whether the user is currently locked out of `verify()` after too many
	 * failed attempts. Use it to surface a "try again later" message.
	 */
	isLocked(userId: string): boolean {
		return this.#isLocked(userId);
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

	/** Remove a factor (e.g. the user disables their authenticator). */
	async disableFactor(factorId: string): Promise<void> {
		await this.#store.delete(factorId);
	}

	#isLocked(userId: string): boolean {
		const entry = this.#attempts.get(userId);
		if (!entry) {
			return false;
		}
		if (entry.resetAt < Date.now()) {
			this.#attempts.delete(userId);
			return false;
		}
		return entry.count >= this.#maxAttempts;
	}

	#recordFailure(userId: string): void {
		const now = Date.now();
		let entry = this.#attempts.get(userId);
		if (!entry || entry.resetAt < now) {
			entry = { count: 0, resetAt: now + this.#windowMs };
			this.#attempts.set(userId, entry);
		}
		entry.count++;
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

function newId(): string {
	return randomBytes(16).toString("hex");
}
