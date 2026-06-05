/**
 * Bouncer — Layer 2 (EVALUATION) of Warden's unified authorization (Epic 56).
 *
 * A Bouncer-faithful evaluation core (verified context7 `/adonisjs/bouncer`,
 * 2026-06-01): standalone abilities via `Bouncer.ability`, class-based policies
 * via `with(Policy)`, the four verbs `allows`/`denies`/`authorize`/`execute`,
 * and guest-denied-by-default. The user is `UserPayload | null` (guest = null,
 * D3); `authorize` throws `WARDEN_AUTHORIZATION_FAILURE` carrying `status: 403`
 * (D2). 56.2 ships PURE mechanics — it does NOT consult the Layer-1
 * `RightsResolver` (D4); abilities/policy methods receive `(user, ...args)` and
 * the developer writes the predicate, exactly as Adonis does.
 */

import type { UserPayload } from "../AuthManager.js";
import { WardenError } from "../errors.js";
import type { RightsResolver } from "../rights/RightsResolver.js";
import type { EffectivePermissions, Scope } from "../rights/types.js";
import { AuthorizationResponse } from "./AuthorizationResponse.js";
import type { BasePolicy } from "./BasePolicy.js";
import { evaluate, isAction, throwAuthorizationFailure } from "./evaluate.js";
import { PolicyAuthorizer } from "./PolicyAuthorizer.js";
import { emptyPermissions } from "./policyContext.js";
import type {
	Ability,
	AbilityOptions,
	AuthorizerResponse,
	BouncerContext,
} from "./types.js";

export class Bouncer {
	readonly #user: UserPayload | null;
	readonly #abilities: Record<string, Ability<never[]>>;
	readonly #policies: Record<string, new () => BasePolicy>;
	readonly #scope: Scope;
	readonly #resolver: RightsResolver | undefined;
	/** Memoized resolution — a Bouncer is fixed per `(user, scope)`, so resolve once (D3). */
	#resolved: Promise<EffectivePermissions> | undefined;

	constructor(
		user: UserPayload | null,
		abilities?: Record<string, Ability<never[]>>,
		policies?: Record<string, new () => BasePolicy>,
		context?: BouncerContext,
	) {
		this.#user = user;
		this.#abilities = abilities ?? {};
		this.#policies = policies ?? {};
		this.#scope = context?.scope ?? "global";
		this.#resolver = context?.resolver;
	}

	/** The active resolution scope (default `"global"`). */
	get scope(): Scope {
		return this.#scope;
	}

	/**
	 * Resolve this Bouncer's `(user, scope)` to `EffectivePermissions`, memoized
	 * once per instance (D3). Guest (`user === null`) or no resolver ⇒ empty
	 * permissions — `resolve()` is never called for a guest (D9). 56.6 relocates
	 * this cache to the request context without changing the policy-facing API.
	 */
	#resolvePermissions(): Promise<EffectivePermissions> {
		if (this.#resolved === undefined) {
			this.#resolved =
				this.#resolver !== undefined && this.#user !== null
					? this.#resolver.resolve(this.#user, this.#scope)
					: Promise.resolve(emptyPermissions(this.#scope));
		}
		return this.#resolved;
	}

	/**
	 * Define a standalone ability. Guest (null user) denied by default; pass
	 * `{ allowGuest: true }` to let the callback run for a guest (D5 step 2).
	 */
	static ability<Args extends unknown[]>(
		callback: (user: UserPayload, ...args: Args) => AuthorizerResponse,
	): Ability<Args>;
	static ability<Args extends unknown[]>(
		options: AbilityOptions,
		callback: (user: UserPayload | null, ...args: Args) => AuthorizerResponse,
	): Ability<Args>;
	static ability(
		optionsOrCallback:
			| AbilityOptions
			| ((...args: never[]) => AuthorizerResponse),
		maybeCallback?: (...args: never[]) => AuthorizerResponse,
	): Ability {
		let allowGuest = false;
		let raw: unknown;
		if (typeof optionsOrCallback === "function") {
			raw = optionsOrCallback;
		} else {
			allowGuest = optionsOrCallback.allowGuest ?? false;
			raw = maybeCallback;
		}
		// The typed overloads above carry the real callback signature for the
		// caller; the impl param is the universal-function supertype so both
		// overloads are accepted. `isAction` reinterprets it as the invokable
		// `Action` shape (a type guard, not a cast — a function's parameter types
		// are not observable at runtime).
		if (!isAction(raw)) {
			throw new WardenError(
				"INVALID_ABILITY",
				"Bouncer.ability requires a callback alongside the options object.",
				{ hint: "Bouncer.ability({ allowGuest: true }, (user) => ...)" },
			);
		}
		const callback = raw;
		const execute = (
			user: UserPayload | null,
			...args: unknown[]
		): AuthorizerResponse => callback(user, ...args);
		return { allowGuest, execute };
	}

	/** Convenience — equivalent to `AuthorizationResponse.deny` (Adonis `bouncer.deny`). */
	deny(message?: string, status?: number): AuthorizationResponse {
		return AuthorizationResponse.deny(message, status);
	}

	/** Open a policy for checks (D8 — fresh `new PolicyClass()` per check). */
	with(policy: (new () => BasePolicy) | string): PolicyAuthorizer {
		const factory =
			typeof policy === "string"
				? this.#resolvePolicyClass(policy)
				: () => new policy();
		// The PolicyAuthorizer inherits the Bouncer's scope + the shared memoized
		// resolve so every policy check sees the active `(user, scope)` (AC1/AC3).
		return new PolicyAuthorizer(this.#user, factory, this.#scope, () =>
			this.#resolvePermissions(),
		);
	}

	/** Run an ability check and resolve to the full response. */
	execute<Args extends unknown[]>(
		ability: Ability<Args>,
		...args: Args
	): Promise<AuthorizationResponse>;
	execute(ability: string, ...args: unknown[]): Promise<AuthorizationResponse>;
	execute(
		ability: string | Ability<never[]>,
		...args: unknown[]
	): Promise<AuthorizationResponse> {
		return this.#evaluateAbility(ability, args);
	}

	/** True iff the ability is authorized. Never throws on denial. */
	allows<Args extends unknown[]>(
		ability: Ability<Args>,
		...args: Args
	): Promise<boolean>;
	allows(ability: string, ...args: unknown[]): Promise<boolean>;
	async allows(
		ability: string | Ability<never[]>,
		...args: unknown[]
	): Promise<boolean> {
		return (await this.#evaluateAbility(ability, args)).authorized;
	}

	/** Boolean negation of {@link allows}. Never throws on denial. */
	denies<Args extends unknown[]>(
		ability: Ability<Args>,
		...args: Args
	): Promise<boolean>;
	denies(ability: string, ...args: unknown[]): Promise<boolean>;
	async denies(
		ability: string | Ability<never[]>,
		...args: unknown[]
	): Promise<boolean> {
		return !(await this.#evaluateAbility(ability, args)).authorized;
	}

	/** Resolves on allow; throws `WARDEN_AUTHORIZATION_FAILURE` on deny (D2). */
	authorize<Args extends unknown[]>(
		ability: Ability<Args>,
		...args: Args
	): Promise<void>;
	authorize(ability: string, ...args: unknown[]): Promise<void>;
	async authorize(
		ability: string | Ability<never[]>,
		...args: unknown[]
	): Promise<void> {
		const response = await this.#evaluateAbility(ability, args);
		if (!response.authorized) {
			throwAuthorizationFailure(response);
		}
	}

	async #evaluateAbility(
		ability: string | Ability<never[]>,
		args: unknown[],
	): Promise<AuthorizationResponse> {
		const resolved =
			typeof ability === "string" ? this.#resolveAbility(ability) : ability;
		return evaluate({
			user: this.#user,
			action: typeof ability === "string" ? ability : "(ability)",
			allowGuest: resolved.allowGuest,
			run: (user) => resolved.execute(user, ...args),
			args,
		});
	}

	#resolveAbility(name: string): Ability<never[]> {
		const found = this.#abilities[name];
		if (found === undefined) {
			throw new WardenError(
				"UNKNOWN_ABILITY",
				`No ability "${name}" is registered on this Bouncer.`,
				{ hint: "Register it via new Bouncer(user, { [name]: ability })." },
			);
		}
		return found;
	}

	#resolvePolicyClass(name: string): () => BasePolicy {
		// Lazy: the lookup runs when a verb constructs the policy, so an unknown
		// name surfaces as a promise rejection (like every other verb error),
		// not a synchronous throw at `with()` time.
		return () => {
			const ctor = this.#policies[name];
			if (ctor === undefined) {
				throw new WardenError(
					"UNKNOWN_POLICY",
					`No policy "${name}" is registered on this Bouncer.`,
					{
						hint: "Register it via new Bouncer(user, abilities, { [name]: Policy }).",
					},
				);
			}
			return new ctor();
		};
	}
}
