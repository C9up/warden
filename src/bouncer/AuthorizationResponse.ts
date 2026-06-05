/**
 * AuthorizationResponse — the value type every Bouncer check resolves to.
 *
 * Layer 2 (EVALUATION) of Warden's unified authorization (Epic 56). Faithful
 * to AdonisJS Bouncer's `AuthorizationResponse`: instances are produced only by
 * the `allow()` / `deny()` static constructors (the constructor is private), a
 * denial defaults to HTTP 403, and a `translation` field is carried for shape
 * parity with Adonis's i18n hook (always `undefined` in 56.2 — D6).
 */
export class AuthorizationResponse {
	readonly authorized: boolean;
	readonly message?: string;
	readonly status?: number;
	/** Parity placeholder for an i18n binding (always undefined in 56.2 — D6). */
	readonly translation?: { identifier: string; data?: Record<string, unknown> };

	private constructor(
		authorized: boolean,
		message?: string,
		status?: number,
		translation?: { identifier: string; data?: Record<string, unknown> },
	) {
		this.authorized = authorized;
		this.message = message;
		this.status = status;
		this.translation = translation;
	}

	/** Authorized response (no status). */
	static allow(): AuthorizationResponse {
		return new AuthorizationResponse(true);
	}

	/** Denied response; `status` defaults to 403 (D6). */
	static deny(message?: string, status = 403): AuthorizationResponse {
		return new AuthorizationResponse(false, message, status);
	}
}
