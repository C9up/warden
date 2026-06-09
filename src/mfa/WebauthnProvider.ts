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

/** Transient per-ceremony challenge storage. */
export interface WebauthnChallengeStore {
	save(state: string, challenge: string): Promise<void>;
	/** Return the challenge for `state` and remove it (single-use). */
	take(state: string): Promise<string | null>;
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
	updateCounter(id: string, counter: number): Promise<void>;
}

export class MemoryWebauthnChallengeStore implements WebauthnChallengeStore {
	#store = new Map<string, string>();
	async save(state: string, challenge: string): Promise<void> {
		this.#store.set(state, challenge);
	}
	async take(state: string): Promise<string | null> {
		const c = this.#store.get(state) ?? null;
		this.#store.delete(state);
		return c;
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
	async updateCounter(id: string, counter: number): Promise<void> {
		const p = this.#store.get(id);
		if (p) {
			this.#store.set(id, { ...p, counter });
		}
	}
}

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
				userVerification: "preferred",
			},
		};
		const state = randomBytes(16).toString("hex");
		await this.#challenges.save(state, challenge);
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
		const expectedChallenge = await this.#challenges.take(state);
		if (!expectedChallenge) {
			return { verified: false };
		}
		if (
			!this.#validClientData(
				response.response.clientDataJSON,
				"webauthn.create",
				expectedChallenge,
			)
		) {
			return { verified: false };
		}

		const attestation = decodeCbor(
			base64urlToBuffer(response.response.attestationObject),
		).value;
		if (!(attestation instanceof Map)) {
			return { verified: false };
		}
		const authDataRaw = attestation.get("authData");
		if (!Buffer.isBuffer(authDataRaw)) {
			return { verified: false };
		}
		const authData = parseAuthenticatorData(authDataRaw);
		if (
			!this.#validAuthenticator(authData) ||
			!authData.cosePublicKey ||
			!authData.cosePublicKeyBytes ||
			!authData.credentialId
		) {
			return { verified: false };
		}

		const { alg } = coseToKeyObject(authData.cosePublicKey);
		await this.#credentials.save({
			id: bufferToBase64url(authData.credentialId),
			userId,
			publicKey: bufferToBase64url(authData.cosePublicKeyBytes),
			alg,
			counter: authData.signCount,
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
			userVerification: "preferred",
			allowCredentials: userId
				? allow.map((c) => ({
						id: c.id,
						type: "public-key",
						transports: c.transports,
					}))
				: undefined,
		};
		const state = randomBytes(16).toString("hex");
		await this.#challenges.save(state, challenge);
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
		const expectedChallenge = await this.#challenges.take(state);
		if (!expectedChallenge) {
			return { verified: false };
		}
		if (
			!this.#validClientData(
				response.response.clientDataJSON,
				"webauthn.get",
				expectedChallenge,
			)
		) {
			return { verified: false };
		}

		const stored = await this.#credentials.findById(response.id);
		if (!stored) {
			return { verified: false };
		}

		const authDataRaw = base64urlToBuffer(response.response.authenticatorData);
		const authData = parseAuthenticatorData(authDataRaw);
		if (!this.#validAuthenticator(authData)) {
			return { verified: false };
		}

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
		if (!ok) {
			return { verified: false };
		}

		// Replay guard: a non-zero counter must strictly advance. Authenticators
		// that always report 0 (e.g. many platform passkeys) are exempt.
		if (authData.signCount !== 0 && authData.signCount <= stored.counter) {
			return { verified: false };
		}
		await this.#credentials.updateCounter(stored.id, authData.signCount);
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

	/** Validate authenticator data: rpIdHash match and user-presence flag. */
	#validAuthenticator(authData: {
		rpIdHash: Buffer;
		flags: { up: boolean };
	}): boolean {
		const expectedRpIdHash = sha256(Buffer.from(this.#rpID, "utf8"));
		return authData.flags.up && expectedRpIdHash.equals(authData.rpIdHash);
	}
}

function expectCoseMap(bytes: Buffer): CborMap {
	const decoded = decodeCbor(bytes).value;
	if (!(decoded instanceof Map)) {
		throw new WardenError("INVALID_CREDENTIAL", "stored COSE key is malformed");
	}
	return decoded;
}
