/**
 * Shared evaluation pipeline — the single place that encodes the Adonis Bouncer
 * evaluation order (D5), used by BOTH standalone abilities (no hooks) and policy
 * methods (with `before`/`after`). Pinned by `bouncer-parity.test.ts` (AC-E2).
 *
 * Order: (1) `before` — a boolean or an `AuthorizationResponse` short-circuits
 * the action; (2) guest-deny — `user === null` && !allowGuest ⇒ auto-deny
 * WITHOUT running the action; (3) run the action; (4) `after` — a boolean or an
 * `AuthorizationResponse` overrides.
 *
 * Only `true` or an allowing `AuthorizationResponse` authorises. A hook that
 * returns anything else is ignored (the action runs, the response is kept),
 * and an action that returns anything else is denied — a column that holds
 * `"false"`, a lookup result, a number: what loosely typed code returns must
 * not read as a grant.
 */

import type { UserPayload } from "../AuthManager.js";
import { E_AUTHORIZATION_FAILURE } from "../errors.js";
import { AuthorizationResponse } from "./AuthorizationResponse.js";
import type { AuthorizerResponse, HookResponse } from "./types.js";

/** A policy action method / ability callback, structurally. */
export type Action = (
	user: UserPayload | null,
	...args: unknown[]
) => AuthorizerResponse;

/** Turns whatever an ability returned into an {@link AuthorizationResponse}. */
export type ResponseBuilder = (
	value: boolean | AuthorizationResponse,
) => AuthorizationResponse;

/** The default: boolean sugar → response; an explicit response passes through (D7). */
export const defaultResponseBuilder: ResponseBuilder = (value) => {
	if (value instanceof AuthorizationResponse) {
		return value;
	}
	return value === true
		? AuthorizationResponse.allow()
		: AuthorizationResponse.deny();
};

/** What a check may answer: a boolean or an {@link AuthorizationResponse}. */
function isAuthorizerResult(
	value: unknown,
): value is boolean | AuthorizationResponse {
	return typeof value === "boolean" || value instanceof AuthorizationResponse;
}

/**
 * Boolean sugar → response, through whatever builder is installed.
 *
 * `Bouncer.responseBuilder` replaces it app-wide, which is how you give every
 * bare `return false` a house message and status instead of a naked 403
 * (AdonisJS `Bouncer.responseBuilder`).
 *
 * NAMED DEVIATION — upstream hands an action's raw value to the builder and
 * reads `.authorized` on whatever comes back, so a string or a number denies
 * (and `null` crashes). The builder's type takes a boolean or a response, so
 * a value that is neither reaches it as `false`: the same denial, with the
 * house message, and no crash. A builder that answers something other than an
 * `AuthorizationResponse` is a denial too.
 */
function normalizeResponse(
	value: unknown,
	builder: ResponseBuilder,
): AuthorizationResponse {
	const built = builder(isAuthorizerResult(value) ? value : false);
	return built instanceof AuthorizationResponse
		? built
		: AuthorizationResponse.deny();
}

/**
 * Type guard for a callable action. A function's parameter/return types are not
 * observable at runtime, so this asserts the structural `Action` shape from a
 * `typeof === "function"` check — a type guard (not an `as` cast), the standard
 * escape for dynamic dispatch.
 */
export function isAction(value: unknown): value is Action {
	return typeof value === "function";
}

/**
 * Throw the canonical authorization failure for a denied response (D2) —
 * `E_AUTHORIZATION_FAILURE`, carrying the response so its status, message and
 * translation reach whoever handles the error.
 */
export function throwAuthorizationFailure(
	response: AuthorizationResponse,
): never {
	throw new E_AUTHORIZATION_FAILURE(response);
}

/** Run the D5 evaluation pipeline and resolve to the final response. */
export async function evaluate(params: {
	user: UserPayload | null;
	action: string;
	allowGuest: boolean;
	run: (user: UserPayload | null) => AuthorizerResponse;
	args: unknown[];
	before?: (
		user: UserPayload | null,
		action: string,
		...args: unknown[]
	) => HookResponse;
	after?: (
		user: UserPayload | null,
		action: string,
		result: AuthorizationResponse,
		...args: unknown[]
	) => HookResponse;
	/** Overrides how a bare boolean becomes a response. */
	responseBuilder?: ResponseBuilder;
}): Promise<AuthorizationResponse> {
	const { user, action, allowGuest, run, args, before, after } = params;
	const builder = params.responseBuilder ?? defaultResponseBuilder;

	let response: AuthorizationResponse | undefined;

	// (1) before — a boolean or a response short-circuits the action; any
	// other value is no opinion, as `undefined` is.
	if (before) {
		const early: unknown = await before(user, action, ...args);
		if (isAuthorizerResult(early)) {
			response = normalizeResponse(early, builder);
		}
	}

	// (2) guest-deny + (3) action — only if before did not short-circuit.
	if (response === undefined) {
		if (user === null && !allowGuest) {
			response = AuthorizationResponse.deny();
		} else {
			response = normalizeResponse(await run(user), builder);
		}
	}

	// (4) after — a boolean or a response overrides; any other value keeps the
	// response. Receives the resource args (Adonis
	// `policy.after(user, action, result, ...args)`).
	if (after) {
		const override: unknown = await after(user, action, response, ...args);
		if (isAuthorizerResult(override)) {
			response = normalizeResponse(override, builder);
		}
	}

	return response;
}
