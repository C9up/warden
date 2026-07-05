/**
 * Shared evaluation pipeline — the single place that encodes the Adonis Bouncer
 * evaluation order (D5), used by BOTH standalone abilities (no hooks) and policy
 * methods (with `before`/`after`). Pinned by `bouncer-parity.test.ts` (AC-E2).
 *
 * Order: (1) `before` — a non-`undefined` return short-circuits the action;
 * (2) guest-deny — `user === null` && !allowGuest ⇒ auto-deny WITHOUT running the
 * action; (3) run the action; (4) `after` — a non-`undefined` return overrides.
 */

import type { UserPayload } from "../AuthManager.js";
import { WardenError } from "../errors.js";
import { AuthorizationResponse } from "./AuthorizationResponse.js";
import type { AuthorizerResponse, HookResponse } from "./types.js";

/** A policy action method / ability callback, structurally. */
export type Action = (
	user: UserPayload | null,
	...args: unknown[]
) => AuthorizerResponse;

/** Boolean sugar → response; an explicit response passes through (D7). */
export function normalizeResponse(
	value: boolean | AuthorizationResponse,
): AuthorizationResponse {
	if (value instanceof AuthorizationResponse) {
		return value;
	}
	return value ? AuthorizationResponse.allow() : AuthorizationResponse.deny();
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

/** Throw the canonical authorization failure for a denied response (D2). */
export function throwAuthorizationFailure(
	response: AuthorizationResponse,
): never {
	throw new WardenError(
		"AUTHORIZATION_FAILURE",
		response.message ?? "Authorization failed",
		{
			hint: "The current user is not authorized for this action.",
			status: response.status ?? 403,
		},
	);
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
}): Promise<AuthorizationResponse> {
	const { user, action, allowGuest, run, args, before, after } = params;

	let response: AuthorizationResponse | undefined;

	// (1) before — non-undefined short-circuits the action.
	if (before) {
		const early = await before(user, action, ...args);
		if (early !== undefined) {
			response = normalizeResponse(early);
		}
	}

	// (2) guest-deny + (3) action — only if before did not short-circuit.
	if (response === undefined) {
		if (user === null && !allowGuest) {
			response = AuthorizationResponse.deny();
		} else {
			response = normalizeResponse(await run(user));
		}
	}

	// (4) after — non-undefined overrides. Receives the resource args (Adonis
	// `policy.after(user, action, result, ...args)`).
	if (after) {
		const override = await after(user, action, response, ...args);
		if (override !== undefined) {
			response = normalizeResponse(override);
		}
	}

	return response;
}
