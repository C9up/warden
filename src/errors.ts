/**
 * WardenError — structured error for Warden auth.
 */
export class WardenError extends Error {
	readonly code: string;
	readonly hint?: string;
	/**
	 * Optional HTTP status carried by the error so the HTTP layer can map it
	 * (e.g. an authorization failure carries 403 — Epic 56 / story 56.2, D2).
	 * Additive and optional: callers that omit it behave exactly as before.
	 */
	readonly status?: number;

	constructor(
		code: string,
		message: string,
		options?: { hint?: string; status?: number },
	) {
		super(message);
		this.name = "WardenError";
		this.code = `WARDEN_${code}`;
		this.hint = options?.hint;
		this.status = options?.status;
	}
}
