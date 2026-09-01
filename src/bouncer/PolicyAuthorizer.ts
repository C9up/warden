/**
 * PolicyAuthorizer — the object returned by `bouncer.with(Policy)`. Exposes the
 * same four verbs as the Bouncer, dispatched to a named action method on a
 * freshly-constructed policy instance (D8 — `new PolicyClass()` per check). The
 * `before`/`after` hooks and the per-method `@allowGuest` rule run through the
 * shared D5 pipeline.
 */

import type { UserPayload } from "../AuthManager.js";
import { WardenError } from "../errors.js";
import type { EffectivePermissions, Scope } from "../rights/types.js";
import type { AuthorizationResponse } from "./AuthorizationResponse.js";
import { BasePolicy } from "./BasePolicy.js";
import { getActionMetadata } from "./decorators.js";
import { emitSafely } from "./emitSafely.js";
import {
	type Action,
	evaluate,
	isAction,
	type ResponseBuilder,
	throwAuthorizationFailure,
} from "./evaluate.js";
import { emptyPermissions, setPolicyContext } from "./policyContext.js";
import type { BouncerEmitter } from "./types.js";

/**
 * Resolve a named action method declared anywhere on the policy's own subclass
 * chain (so an action inherited from an intermediate policy base class still
 * dispatches). Rejects `constructor`, the `before`/`after` hooks, and any
 * `BasePolicy`/`Object.prototype` member so a verb call can never dispatch to a
 * non-action method — a guard the adversarial review specifically probes.
 */
function resolveActionMethod(policy: BasePolicy, action: string): Action {
	// Reject the hooks + constructor by name, then accept an action declared
	// anywhere on the policy's own subclass chain — the immediate prototype up to
	// (but not including) BasePolicy.prototype / Object.prototype — so a method
	// inherited from an intermediate policy base class (`class A extends B`) still
	// dispatches, while BasePolicy's own members (scope/permissions getters) and
	// Object.prototype members stay unreachable.
	const isHookOrCtor =
		action === "constructor" || action === "before" || action === "after";
	let declaredHere = false;
	for (
		let proto: object | null = Object.getPrototypeOf(policy);
		proto !== null &&
		proto !== BasePolicy.prototype &&
		proto !== Object.prototype;
		proto = Object.getPrototypeOf(proto)
	) {
		if (Object.hasOwn(proto, action)) {
			declaredHere = true;
			break;
		}
	}
	const candidate: unknown = Reflect.get(policy, action);
	if (isHookOrCtor) {
		declaredHere = false;
	}
	if (!declaredHere || !isAction(candidate)) {
		throw new WardenError(
			"UNKNOWN_POLICY_ACTION",
			`Policy "${policy.constructor.name}" has no action "${action}"`,
			{ hint: "Declare the action as a method on the policy class." },
		);
	}
	return candidate.bind(policy);
}

export class PolicyAuthorizer {
	readonly #user: UserPayload | null;
	readonly #factory: () => Promise<BasePolicy>;
	readonly #scope: Scope;
	readonly #resolvePermissions: () => Promise<EffectivePermissions>;
	#emitter: BouncerEmitter | undefined;
	readonly #responseBuilder: ResponseBuilder | undefined;

	constructor(
		user: UserPayload | null,
		factory: () => Promise<BasePolicy>,
		scope: Scope = "global",
		resolvePermissions: () => Promise<EffectivePermissions> = () =>
			Promise.resolve(emptyPermissions(scope)),
		emitter?: BouncerEmitter,
		responseBuilder?: ResponseBuilder,
	) {
		this.#user = user;
		this.#factory = factory;
		this.#scope = scope;
		this.#resolvePermissions = resolvePermissions;
		this.#emitter = emitter;
		this.#responseBuilder = responseBuilder;
	}

	/** Run a check and resolve to the full response (D8 — fresh policy per check). */
	async execute(
		action: string,
		...args: unknown[]
	): Promise<AuthorizationResponse> {
		const policy = await this.#factory();
		// Attach the active scope + resolved permissions BEFORE dispatch so the
		// before/method/after pipeline all read `this.scope` / `this.permissions`.
		const permissions = await this.#resolvePermissions();
		setPolicyContext(policy, { scope: this.#scope, permissions });
		const method = resolveActionMethod(policy, action);
		const options = getActionMetadata(policy, action);
		const response = await evaluate({
			user: this.#user,
			action,
			allowGuest: options.allowGuest ?? false,
			run: (user) => method(user, ...args),
			args,
			before: policy.before?.bind(policy),
			after: policy.after?.bind(policy),
			responseBuilder: this.#responseBuilder,
		});
		emitSafely(this.#emitter, "authorization:finished", {
			user: this.#user,
			action,
			// Same payload as an ability check: which resource the decision was
			// about, not just that a decision happened.
			parameters: args,
			response,
		});
		return response;
	}

	/**
	 * Swap the event sink after construction (AdonisJS `setEmitter`).
	 *
	 * The Bouncer passes its own down, but an authorizer built directly — a
	 * test, a console command — had no way to be given one.
	 */
	setEmitter(emitter?: BouncerEmitter): this {
		this.#emitter = emitter;
		return this;
	}

	/** True iff the action is authorized. Never throws on denial. */
	async allows(action: string, ...args: unknown[]): Promise<boolean> {
		return (await this.execute(action, ...args)).authorized;
	}

	/** Boolean negation of {@link allows}. Never throws on denial. */
	async denies(action: string, ...args: unknown[]): Promise<boolean> {
		return !(await this.execute(action, ...args)).authorized;
	}

	/** Resolves on allow; throws `AUTHORIZATION_FAILURE` on deny (D2). */
	async authorize(action: string, ...args: unknown[]): Promise<void> {
		const response = await this.execute(action, ...args);
		if (!response.authorized) {
			throwAuthorizationFailure(response);
		}
	}
}
