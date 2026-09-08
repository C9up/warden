/**
 * WebauthnProvider — passkeys / FIDO2 via WebAuthn, implemented in-house on
 * `node:crypto` (see `webauthn-codec.ts`). No third-party dependency: warden
 * keeps its zero-runtime-dependency footprint.
 *
 * The browser side produces the standard `PublicKeyCredential` JSON; this
 * provider builds the ceremony options and verifies the responses server-side.
 *
 * Attestation statements are NOT verified — this is a deliberate
 * trust-on-registration posture (request `attestation: "none"` on the client),
 * which is what the vast majority of relying parties use for 2FA / passkeys.
 * Full attestation (packed/tpm/apple/MDS cert-chain validation) can be layered
 * on later without changing this API.
 *
 * Both the per-ceremony challenge and the persisted passkeys go through
 * pluggable stores (in-memory defaults), mirroring the rest of warden.
 */

import { randomBytes } from "node:crypto";
import { WardenError } from "../errors.js";
import {
	base64urlToBuffer,
	bufferToBase64url,
	type CborMap,
	coseToKeyObject,
	decodeCbor,
	parseAuthenticatorData,
	sha256,
	verifyWebauthnSignature,
} from "./webauthn-codec.js";

/** Browser → server payload from `navigator.credentials.create()`. */
export interface RegistrationResponseJSON {
	id: string;
	rawId: string;
	type: "public-key";
	response: {
		clientDataJSON: string;
		attestationObject: string;
		transports?: string[];
	};
}

/** Browser → server payload from `navigator.credentials.get()`. */
export interface AuthenticationResponseJSON {
	id: string;
	rawId: string;
	type: "public-key";
	response: {
		clientDataJSON: string;
		authenticatorData: string;
		signature: string;
		userHandle?: string;
	};
}

export interface RegistrationOptionsJSON {
	challenge: string;
	rp: { name: string; id: string };
	user: { id: string; name: string; displayName: string };
	pubKeyCredParams: Array<{ type: "public-key"; alg: number }>;
	timeout: number;
	attestation: "none";
	excludeCredentials: Array<{
		id: string;
		type: "public-key";
		transports?: string[];
	}>;
	authenticatorSelection: { residentKey: string; userVerification: string };
}

export interface AuthenticationOptionsJSON {
	challenge: string;
	timeout: number;
	rpId: string;
	userVerification: string;
	allowCredentials?: Array<{
		id: string;
		type: "public-key";
		transports?: string[];
	}>;
}

/**
 * Transient per-ceremony challenge storage.
 *
 * Implementations MUST be **time-bound**: a challenge that is never consumed has
 * to expire server-side (single-use alone is not enough — an unconsumed
 * challenge left live indefinitely widens the replay/relay window). A DB/Redis
 * store should use a TTL column / `EXPIRE`; the in-memory default stamps an
 * `expiresAt` and refuses an expired challenge in `take`.
 */
/**
 * What a pending ceremony holds.
 *
 * The identity is stored WITH the challenge, and that is the point. A store
 * that kept only `state -> challenge` let `finishRegistration` be handed any
 * `userId` the caller produced: an integration that read it back from the
 * request, or whose session changed between the two steps, attached a valid
 * passkey to the wrong account — a working credential on someone else's login.
 */
export interface WebauthnCeremony {
	challenge: string;
	/**
	 * The user this ceremony was started for. Absent only for a usernameless
	 * authentication, where the credential itself names the owner.
	 */
	userId?: string;
}

export interface WebauthnChallengeStore {
	save(state: string, ceremony: WebauthnCeremony): Promise<void>;
	/**
	 * Return the ceremony for `state` and remove it (single-use). MUST return
	 * `null` if the stored ceremony has passed its TTL.
	 */
	take(state: string): Promise<WebauthnCeremony | null>;
}

/** A registered passkey, persisted between ceremonies. */
export interface StoredPasskey {
	/** Base64URL credential id. */
	id: string;
	userId: string;
	/** Base64URL of the raw COSE public-key bytes. */
	publicKey: string;
	/** COSE algorithm id (e.g. -7 for ES256). */
	alg: number;
	counter: number;
	transports?: string[];
}

export interface WebauthnCredentialStore {
	save(passkey: StoredPasskey): Promise<void>;
	findById(id: string): Promise<StoredPasskey | null>;
	findByUser(userId: string): Promise<StoredPasskey[]>;
	/**
	 * Advance the signature counter, and ONLY from the value that was read.
	 *
	 * The counter is the whole of the cloned-authenticator defence: a clone
	 * replays a lower count than the real device has reached, and the mismatch
	 * is what betrays it. Read-compare-write across `findById` and a plain
	 * `updateCounter` let two concurrent assertions read the same old value,
	 * both pass, and then write in either order — so the stored counter could
	 * go BACKWARDS and the guard lost the only evidence it has.
	 *
	 * Returns `false` when the stored value is no longer `expected`, which
	 * means another assertion won the race and this one must be refused. A
	 * persistent store implements it as a conditional write:
	 *
	 *   SQL    UPDATE … SET counter = $next WHERE id = $id AND counter = $expected
	 *   Redis  a WATCH/MULTI, or a Lua compare-and-set
	 */
	advanceCounter(id: string, expected: number, next: number): Promise<boolean>;
}

/**
 * Run a parse of attacker-supplied bytes, turning a throw into "invalid".
 *
 * A truncated attestation, a malformed COSE key or authenticator data that
 * stops mid-structure are INPUT errors — `CBOR: item starts past the end of the
 * buffer` reaching the caller is a 500 for a bad request, and a 500 tells
 * whoever sent it that they reached something which did not expect them.
 *
 * Deliberately narrow: only the decoding and the signature check go through
 * here. A store that cannot be read is infrastructure, and reporting an outage
 * as "not verified" would let a database failure read as a failed login.
 */
function parsePayload<T>(parse: () => T | null): T | null {
	try {
		return parse();
	} catch {
		return null;
	}
}

export class MemoryWebauthnChallengeStore implements WebauthnChallengeStore {
	#store = new Map<string, WebauthnCeremony & { expiresAt: number }>();
	readonly #ttlMs: number;

	/**
	 * @param ttlMs Server-side challenge lifetime. Default 5 min.
	 * @param maxEntries How many pending ceremonies this process will hold.
	 *   Sweeping removes only EXPIRED entries, so a flood of still-valid ones
	 *   grew the map without a ceiling. Default 10 000.
	 */
	constructor(ttlMs = 300_000, maxEntries = 10_000) {
		// A TTL of Infinity or NaN is not a TTL: the challenge never expires,
		// against a contract that says it MUST be time-bound — and an unconsumed
		// challenge left live indefinitely is exactly the replay window the
		// expiry exists to close.
		if (!Number.isInteger(ttlMs) || ttlMs < 1) {
			throw new WardenError(
				"E_WARDEN_STORE_TTL_INVALID",
				`ttlMs must be a positive integer, got ${String(ttlMs)}.`,
				{
					hint: "Give the ceremony a lifetime in milliseconds — the default is 300000 (5 min).",
				},
			);
		}
		this.#ttlMs = ttlMs;
		// A ceiling of 0, a negative, NaN or Infinity is not a ceiling: the
		// first two refuse every write and the last two disable the bound this
		// exists to provide, silently. A caller asking for one of those means
		// something, and none of the meanings is what would have happened.
		if (!Number.isInteger(maxEntries) || maxEntries < 1) {
			throw new WardenError(
				"E_WARDEN_STORE_LIMIT_INVALID",
				`maxEntries must be a positive integer, got ${String(maxEntries)}.`,
				{
					hint: "Pass the number of pending entries this process may hold — the default is 10_000.",
				},
			);
		}
		this.#maxEntries = maxEntries;
	}

	/**
	 * Size at which the next sweep runs, doubling each time.
	 *
	 * Entries only ever left when their state was reused or taken, so a
	 * ceremony nobody finished — a passkey prompt dismissed, which happens all
	 * day — stayed for the life of the process. Sweeping on write bounds it
	 * without a timer, which would hold the event loop open and need a disposal
	 * contract this store does not have.
	 */
	#sweepAt = 64;
	readonly #maxEntries: number;

	async save(state: string, ceremony: WebauthnCeremony): Promise<void> {
		if (this.#store.size >= this.#maxEntries && !this.#store.has(state)) {
			this.#sweep();
		}
		if (this.#store.size >= this.#maxEntries && !this.#store.has(state)) {
			// Refused rather than evicted: making room by dropping someone
			// else's pending ceremony is how a flood locks a real user out.
			throw new WardenError(
				"E_WARDEN_WEBAUTHN_STORE_FULL",
				`The in-memory WebAuthn challenge store is full (${this.#maxEntries} pending ceremonies).`,
				{
					hint: "Rate-limit the endpoint that starts a ceremony, or move to a persistent store with its own TTL.",
				},
			);
		}
		this.#store.set(state, {
			...ceremony,
			expiresAt: Date.now() + this.#ttlMs,
		});
		if (this.#store.size > this.#sweepAt) this.#sweep();
	}

	/** Drop everything already expired. */
	#sweep(): void {
		const now = Date.now();
		for (const [state, entry] of this.#store) {
			if (entry.expiresAt < now) this.#store.delete(state);
		}
		this.#sweepAt = Math.max(64, this.#store.size * 2);
	}
	async take(state: string): Promise<WebauthnCeremony | null> {
		const entry = this.#store.get(state);
		this.#store.delete(state); // single-use regardless of freshness
		// `<=`, not `<`: an entry whose deadline is exactly now has expired.
		// Strictly-less left it valid for the remainder of that millisecond.
		if (!entry || entry.expiresAt <= Date.now()) {
			return null;
		}
		return { challenge: entry.challenge, userId: entry.userId };
	}
}

export class MemoryWebauthnCredentialStore implements WebauthnCredentialStore {
	#store = new Map<string, StoredPasskey>();
	async save(passkey: StoredPasskey): Promise<void> {
		this.#store.set(passkey.id, passkey);
	}
	async findById(id: string): Promise<StoredPasskey | null> {
		return this.#store.get(id) ?? null;
	}
	async findByUser(userId: string): Promise<StoredPasskey[]> {
		return [...this.#store.values()].filter((p) => p.userId === userId);
	}
	/**
	 * Atomic here for free: a synchronous read, compare and write with no
	 * `await` between them cannot be interleaved on a single-threaded runtime.
	 * Written as one block on purpose — an `await` inside would silently
	 * reintroduce the race this exists to close.
	 */
	async advanceCounter(
		id: string,
		expected: number,
		next: number,
	): Promise<boolean> {
		const p = this.#store.get(id);
		if (!p || p.counter !== expected) return false;
		this.#store.set(id, { ...p, counter: next });
		return true;
	}
}

/** WebAuthn user-verification requirement (PIN / biometric). */
export type UserVerificationRequirement =
	| "required"
	| "preferred"
	| "discouraged";

export interface WebauthnConfig {
	/** Human-readable relying-party name (your app). */
	rpName: string;
	/** Relying-party ID — your registrable domain (e.g. `fluveo.ch`). */
	rpID: string;
	/** Expected origin(s) of the ceremony (e.g. `https://fluveo.ch`). */
	origin: string | string[];
	challengeStore?: WebauthnChallengeStore;
	credentialStore?: WebauthnCredentialStore;
	/** Ceremony timeout in ms. Default `60000`. */
	timeout?: number;
	/**
	 * COSE algorithms offered to the authenticator, in preference order.
	 * Default ES256, RS256, EdDSA.
	 */
	supportedAlgorithms?: number[];
	/**
	 * User-verification requirement. Default `"preferred"`. Set `"required"`
	 * for strong MFA / sensitive passkeys — the ceremony then requests UV AND
	 * the server rejects an assertion whose authenticator-data UV flag is unset
	 * (a mere user-presence touch no longer satisfies the check).
	 */
	userVerification?: UserVerificationRequirement;
}

export interface WebauthnUser {
	id: string;
	name: string;
	displayName?: string;
}

const DEFAULT_ALGS = [-7, -257, -8];

export class WebauthnProvider {
	readonly kind = "webauthn" as const;
	readonly #rpName: string;
	readonly #rpID: string;
	readonly #origins: string[];
	readonly #timeout: number;
	readonly #algorithms: number[];
	readonly #userVerification: UserVerificationRequirement;
	readonly #challenges: WebauthnChallengeStore;
	readonly #credentials: WebauthnCredentialStore;

	constructor(config: WebauthnConfig) {
		if (!config?.rpID || !config?.rpName || !config?.origin) {
			throw new WardenError(
				"INVALID_CONFIG",
				"WebauthnProvider requires rpName, rpID and origin",
			);
		}
		this.#rpName = config.rpName;
		this.#rpID = config.rpID;
		this.#origins = Array.isArray(config.origin)
			? config.origin
			: [config.origin];
		this.#timeout = config.timeout ?? 60_000;
		this.#algorithms = config.supportedAlgorithms ?? DEFAULT_ALGS;
		this.#userVerification = config.userVerification ?? "preferred";
		this.#challenges =
			config.challengeStore ?? new MemoryWebauthnChallengeStore();
		this.#credentials =
			config.credentialStore ?? new MemoryWebauthnCredentialStore();
	}

	/**
	 * Begin passkey registration. Returns the options to hand to the browser,
	 * plus an opaque `state` token the caller stashes in the session and passes
	 * back to `finishRegistration()`.
	 */
	async startRegistration(
		user: WebauthnUser,
	): Promise<{ options: RegistrationOptionsJSON; state: string }> {
		const existing = await this.#credentials.findByUser(user.id);
		const challenge = bufferToBase64url(randomBytes(32));
		const options: RegistrationOptionsJSON = {
			challenge,
			rp: { name: this.#rpName, id: this.#rpID },
			user: {
				id: bufferToBase64url(Buffer.from(user.id, "utf8")),
				name: user.name,
				displayName: user.displayName ?? user.name,
			},
			pubKeyCredParams: this.#algorithms.map((alg) => ({
				type: "public-key",
				alg,
			})),
			timeout: this.#timeout,
			attestation: "none",
			excludeCredentials: existing.map((c) => ({
				id: c.id,
				type: "public-key",
				transports: c.transports,
			})),
			authenticatorSelection: {
				residentKey: "preferred",
				userVerification: this.#userVerification,
			},
		};
		const state = randomBytes(16).toString("hex");
		// The identity travels WITH the challenge. Stored apart, `finish` had to
		// trust whatever `userId` the caller handed back.
		await this.#challenges.save(state, { challenge, userId: user.id });
		return { options, state };
	}

	/**
	 * Complete registration: validate client data + authenticator data against
	 * the stored challenge and persist the new passkey on success.
	 */
	async finishRegistration(
		state: string,
		userId: string,
		response: RegistrationResponseJSON,
	): Promise<{ verified: boolean }> {
		const ceremony = await this.#challenges.take(state);
		if (!ceremony) {
			return { verified: false };
		}
		// The passkey is registered for the user who STARTED the ceremony, not
		// for whoever the caller names now. A mismatch is an integration reading
		// the id back from the request, or a session that changed between the
		// two steps; either way it would attach a working credential to the
		// wrong account, so it is refused rather than resolved in someone's
		// favour.
		if (ceremony.userId !== undefined && ceremony.userId !== userId) {
			return { verified: false };
		}
		if (
			!this.#validClientData(
				response.response.clientDataJSON,
				"webauthn.create",
				ceremony.challenge,
			)
		) {
			return { verified: false };
		}

		// The payload is attacker-supplied: a truncated attestation, a malformed
		// COSE key or authenticator data that stops mid-structure are INPUT
		// errors, and this method promises `{ verified: false }` for an invalid
		// response. Letting the decoder's exception out turned a bad request
		// into a 500 — and a 500 tells whoever sent it that they reached
		// something that did not expect them.
		//
		// Only the parsing is wrapped: a store that cannot be read is
		// infrastructure, and swallowing that would report "not verified" for an
		// outage.
		const parsed = parsePayload(() => {
			const attestation = decodeCbor(
				base64urlToBuffer(response.response.attestationObject),
			).value;
			if (!(attestation instanceof Map)) return null;
			const authDataRaw = attestation.get("authData");
			if (!Buffer.isBuffer(authDataRaw)) return null;
			const authData = parseAuthenticatorData(authDataRaw);
			if (
				!this.#validAuthenticator(authData) ||
				!authData.cosePublicKey ||
				!authData.cosePublicKeyBytes ||
				!authData.credentialId
			) {
				return null;
			}
			// The narrowing is carried OUT of the closure: the guard above proved
			// these three are present, and the caller cannot see that through an
			// object literal typed from `authData` alone.
			return {
				credentialId: authData.credentialId,
				publicKeyBytes: authData.cosePublicKeyBytes,
				signCount: authData.signCount,
				alg: coseToKeyObject(authData.cosePublicKey).alg,
			};
		});
		if (parsed === null) {
			return { verified: false };
		}
		await this.#credentials.save({
			id: bufferToBase64url(parsed.credentialId),
			userId,
			publicKey: bufferToBase64url(parsed.publicKeyBytes),
			alg: parsed.alg,
			counter: parsed.signCount,
			transports: response.response.transports,
		});
		return { verified: true };
	}

	/**
	 * Begin authentication. Pass `userId` to restrict to that user's passkeys
	 * (2FA step); omit it for a usernameless / discoverable-credential sign-in.
	 */
	async startAuthentication(
		userId?: string,
	): Promise<{ options: AuthenticationOptionsJSON; state: string }> {
		const challenge = bufferToBase64url(randomBytes(32));
		const allow = userId ? await this.#credentials.findByUser(userId) : [];
		const options: AuthenticationOptionsJSON = {
			challenge,
			timeout: this.#timeout,
			rpId: this.#rpID,
			userVerification: this.#userVerification,
			allowCredentials: userId
				? allow.map((c) => ({
						id: c.id,
						type: "public-key",
						transports: c.transports,
					}))
				: undefined,
		};
		const state = randomBytes(16).toString("hex");
		// `userId` is optional here: a usernameless login is named by the
		// credential itself. When it IS given, storing it lets `finish` refuse an
		// assertion from someone else's passkey.
		await this.#challenges.save(state, { challenge, userId });
		return { options, state };
	}

	/**
	 * Complete authentication: look up the asserted credential, verify the
	 * signature against the stored challenge, and advance the replay counter.
	 * Returns the owning `userId` on success.
	 */
	async finishAuthentication(
		state: string,
		response: AuthenticationResponseJSON,
	): Promise<{ verified: boolean; userId?: string }> {
		const ceremony = await this.#challenges.take(state);
		if (!ceremony) {
			return { verified: false };
		}
		if (
			!this.#validClientData(
				response.response.clientDataJSON,
				"webauthn.get",
				ceremony.challenge,
			)
		) {
			return { verified: false };
		}

		const stored = await this.#credentials.findById(response.id);
		if (!stored) {
			return { verified: false };
		}
		// When the ceremony named a user, the asserted credential has to be
		// theirs. `allowCredentials` is a HINT the browser may ignore and an
		// attacker simply will: without this, a login started for one account
		// could be completed with a passkey belonging to another.
		if (ceremony.userId !== undefined && stored.userId !== ceremony.userId) {
			return { verified: false };
		}

		// Same reasoning as registration: the payload is attacker-supplied, and
		// this method promises `{ verified: false }` for an invalid one. Only
		// the parsing and the signature check are wrapped — a store failure is
		// infrastructure and must not be reported as "not verified".
		const checked = parsePayload(() => {
			const authDataRaw = base64urlToBuffer(
				response.response.authenticatorData,
			);
			const authData = parseAuthenticatorData(authDataRaw);
			if (!this.#validAuthenticator(authData)) return null;

			// Signed payload = authenticatorData ‖ SHA-256(clientDataJSON).
			const clientHash = sha256(
				base64urlToBuffer(response.response.clientDataJSON),
			);
			const signedData = Buffer.concat([authDataRaw, clientHash]);
			const { key } = coseToKeyObject(
				expectCoseMap(base64urlToBuffer(stored.publicKey)),
			);
			const ok = verifyWebauthnSignature(
				stored.alg,
				key,
				signedData,
				base64urlToBuffer(response.response.signature),
			);
			return ok ? { authData } : null;
		});
		if (checked === null) {
			return { verified: false };
		}
		const { authData } = checked;

		// Replay guard: a non-zero counter must strictly advance. Authenticators
		// that always report 0 (e.g. many platform passkeys) are exempt.
		if (authData.signCount !== 0 && authData.signCount <= stored.counter) {
			return { verified: false };
		}
		// The write is what decides. Comparing here and writing unconditionally
		// let a second assertion that read the same old counter also pass, and
		// whichever wrote last set the stored value — possibly backwards.
		// Refusing when the counter has moved under us costs a legitimate user
		// one retry and costs a clone the whole attack.
		const advanced = await this.#credentials.advanceCounter(
			stored.id,
			stored.counter,
			authData.signCount,
		);
		if (!advanced) {
			return { verified: false };
		}
		return { verified: true, userId: stored.userId };
	}

	/** Validate clientDataJSON: type, challenge match, and origin allow-list. */
	#validClientData(
		clientDataB64: string,
		expectedType: "webauthn.create" | "webauthn.get",
		expectedChallenge: string,
	): boolean {
		let parsed: { type?: string; challenge?: string; origin?: string };
		try {
			parsed = JSON.parse(base64urlToBuffer(clientDataB64).toString("utf8"));
		} catch {
			return false;
		}
		return (
			parsed.type === expectedType &&
			parsed.challenge === expectedChallenge &&
			typeof parsed.origin === "string" &&
			this.#origins.includes(parsed.origin)
		);
	}

	/**
	 * Validate authenticator data: rpIdHash match, mandatory user-presence, and
	 * — when `userVerification: "required"` is configured — the user-verification
	 * flag (PIN / biometric actually performed, not just a presence touch).
	 */
	#validAuthenticator(authData: {
		rpIdHash: Buffer;
		flags: { up: boolean; uv: boolean };
	}): boolean {
		const expectedRpIdHash = sha256(Buffer.from(this.#rpID, "utf8"));
		if (!authData.flags.up || !expectedRpIdHash.equals(authData.rpIdHash)) {
			return false;
		}
		if (this.#userVerification === "required" && !authData.flags.uv) {
			return false;
		}
		return true;
	}
}

function expectCoseMap(bytes: Buffer): CborMap {
	const decoded = decodeCbor(bytes).value;
	if (!(decoded instanceof Map)) {
		throw new WardenError("INVALID_CREDENTIAL", "stored COSE key is malformed");
	}
	return decoded;
}
