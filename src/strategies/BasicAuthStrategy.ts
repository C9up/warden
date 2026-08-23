/**
 * HTTP Basic authentication (AdonisJS `basic_auth` guard).
 *
 * The browser prompts for credentials and resends them on every request; there
 * is no session and nothing to log out of. That makes it the right fit for a
 * machine-to-machine endpoint or an internal tool behind TLS, and the wrong fit
 * for a user-facing login — the credentials travel on EVERY request, so without
 * TLS they are exposed on every one of them.
 */

import { timingSafeEqual } from "node:crypto";
import type {
	AuthClientResponse,
	AuthResult,
	AuthStrategy,
	UserPayload,
} from "../AuthManager.js";

export interface BasicAuthConfig {
	/**
	 * Resolve a user by the username half of the header, and say whether the
	 * password matches. Returning null is an unknown user.
	 */
	verifyCredentials: (
		uid: string,
		password: string,
	) => Promise<UserPayload | null>;
	/**
	 * The realm announced in `WWW-Authenticate`. The browser shows it in its
	 * prompt, so it should name what is being unlocked.
	 */
	realm?: string;
}

/** The `WWW-Authenticate` value a 401 must carry for the browser to prompt. */
export function basicAuthChallenge(realm = "Restricted"): string {
	// The realm is quoted, so a quote inside it would end the field early.
	return `Basic realm="${realm.replace(/["\\]/g, "")}", charset="UTF-8"`;
}

/**
 * Split an `Authorization: Basic` header into its two halves.
 *
 * RFC 7617 splits on the FIRST colon: a password may contain colons, a username
 * may not. Splitting on the last one would silently accept the wrong pair.
 */
export function decodeBasicAuth(
	header: string | undefined,
): { uid: string; password: string } | null {
	if (!header) return null;
	const [scheme, encoded] = header.split(" ");
	if ((scheme ?? "").toLowerCase() !== "basic" || !encoded) return null;
	let decoded: string;
	try {
		decoded = Buffer.from(encoded, "base64").toString("utf8");
	} catch {
		return null;
	}
	const separator = decoded.indexOf(":");
	if (separator === -1) return null;
	return {
		uid: decoded.slice(0, separator),
		password: decoded.slice(separator + 1),
	};
}

export class BasicAuthStrategy implements AuthStrategy {
	name = "basic_auth";
	readonly #config: BasicAuthConfig;

	constructor(config: BasicAuthConfig) {
		this.#config = config;
	}

	/** The challenge to send with a 401 so the browser prompts. */
	get challenge(): string {
		return basicAuthChallenge(this.#config.realm);
	}

	/** Authenticate a `{ uid, password }` pair directly. */
	async authenticate(
		credentials: Record<string, unknown>,
	): Promise<AuthResult> {
		const uid = credentials.uid ?? credentials.username ?? credentials.email;
		const password = credentials.password;
		if (typeof uid !== "string" || typeof password !== "string") {
			return { authenticated: false, error: "Invalid credentials" };
		}
		const user = await this.#config.verifyCredentials(uid, password);
		// One message for an unknown user and for a wrong password: telling them
		// apart turns the endpoint into a username oracle.
		if (!user) return { authenticated: false, error: "Invalid credentials" };
		return { authenticated: true, user };
	}

	/** Authenticate from the raw `Authorization` header value. */
	async verify(header: string): Promise<AuthResult> {
		const decoded = decodeBasicAuth(header);
		if (!decoded) return { authenticated: false, error: "Invalid credentials" };
		return this.authenticate(decoded);
	}

	/**
	 * Build the header a client sends (AdonisJS `authenticateAsClient`) — what a
	 * test uses to act as a user without reproducing the encoding by hand.
	 */
	authenticateAsClient(uid: string, password: string): AuthClientResponse {
		const encoded = Buffer.from(`${uid}:${password}`, "utf8").toString(
			"base64",
		);
		return { headers: { authorization: `Basic ${encoded}` } };
	}
}

/**
 * Compare two secrets without leaking how far they matched.
 *
 * Exposed because an app implementing `verifyCredentials` against a plaintext
 * shared secret needs it — a plain `===` returns sooner on an early mismatch,
 * and that difference is measurable.
 */
export function safeCompare(a: string, b: string): boolean {
	const left = Buffer.from(a, "utf8");
	const right = Buffer.from(b, "utf8");
	if (left.length !== right.length) return false;
	return timingSafeEqual(left, right);
}
