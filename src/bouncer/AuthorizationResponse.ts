/**
 * AuthorizationResponse — the value type every Bouncer check resolves to.
 *
 * Layer 2 (EVALUATION) of Warden's unified authorization (Epic 56). Faithful
 * to AdonisJS Bouncer's `AuthorizationResponse`: instances are produced only by
 * the `allow()` / `deny()` static constructors (the constructor is private). A
 * denial carries no `status` unless one is passed — the HTTP 403 default is
 * applied only at the throw/HTTP boundary (Adonis parity) — and a `translation`
 * field carries the i18n binding set via {@link t}.
 */
export class AuthorizationResponse {
	readonly authorized: boolean;
	message?: string;
	status?: number;
	/** i18n binding set via {@link t} (Adonis `AuthorizationResponse.t`). */
	translation?: { identifier: string; data?: Record<string, unknown> };

	/**
	 * Private because a response is only ever built through allow() / deny(), so the pair stays consistent.
	 *
	 * `private` and not `#`: a private CONSTRUCTOR has no native form. It is the
	 * one place the keyword expresses something `#` cannot.
	 */
	private constructor(authorized: boolean, message?: string, status?: number) {
		this.authorized = authorized;
		this.message = message;
		this.status = status;
	}

	/** Authorized response (no status). */
	static allow(): AuthorizationResponse {
		return new AuthorizationResponse(true);
	}

	/**
	 * Denied response. `status` is left `undefined` unless passed — the 403
	 * default is applied only when the denial is thrown / mapped to HTTP (Adonis
	 * parity).
	 */
	static deny(message?: string, status?: number): AuthorizationResponse {
		return new AuthorizationResponse(false, message, status);
	}

	/**
	 * Set the i18n translation binding and return `this` for chaining (Adonis
	 * `AuthorizationResponse.t`), e.g. `AuthorizationResponse.deny().t('errors.forbidden')`.
	 */
	t(identifier: string, data?: Record<string, unknown>): this {
		this.translation = { identifier, data };
		return this;
	}
}
