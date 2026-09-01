/**
 * Bouncer — Layer 2 (EVALUATION) of Warden's unified authorization (Epic 56).
 *
 * A Bouncer-faithful evaluation core (verified context7 `/adonisjs/bouncer`,
 * 2026-06-01): standalone abilities via `Bouncer.ability`, class-based policies
 * via `with(Policy)`, the four verbs `allows`/`denies`/`authorize`/`execute`,
 * and guest-denied-by-default. The user is `UserPayload | null` (guest = null,
 * D3); `authorize` throws `AUTHORIZATION_FAILURE` carrying `status: 403`
 * (D2). 56.2 ships PURE mechanics — it does NOT consult the Layer-1
 * `RightsResolver` (D4); abilities/policy methods receive `(user, ...args)` and
 * the developer writes the predicate, exactly as Adonis does.
 */

import type { UserPayload } from "../AuthManager.js";
import { WardenError } from "../errors.js";
import type { RightsResolver } from "../rights/RightsResolver.js";
import type { EffectivePermissions, Scope } from "../rights/types.js";
import { AbilitiesBuilder } from "./AbilitiesBuilder.js";
import { AuthorizationResponse } from "./AuthorizationResponse.js";
import type { BasePolicy } from "./BasePolicy.js";
import { emitSafely } from "./emitSafely.js";
import {
	defaultResponseBuilder,
	evaluate,
	isAction,
	type ResponseBuilder,
	throwAuthorizationFailure,
} from "./evaluate.js";
import { PolicyAuthorizer } from "./PolicyAuthorizer.js";
import { emptyPermissions } from "./policyContext.js";
import type {
	Ability,
	AbilityOptions,
	AuthorizerResponse,
	BouncerContext,
	BouncerEmitter,
	PolicyContainerResolver,
} from "./types.js";

export class Bouncer {
	/**
	 * How a bare boolean from an ability or a policy becomes an
	 * {@link AuthorizationResponse} (AdonisJS `Bouncer.responseBuilder`).
	 *
	 * Replace it once at boot to give every `return false` a house message and
	 * status instead of a naked 403:
	 *
	 * ```ts
	 * Bouncer.responseBuilder = (value) =>
	 *   value === false ? AuthorizationResponse.deny('Nope', 404) : normalizeResponse(value)
	 * ```
	 */
	static responseBuilder: ResponseBuilder = defaultResponseBuilder;

	readonly #userOrResolver: UserPayload | (() => UserPayload | null) | null;
	/** Lazily-resolved user cache (`undefined` until `#getUser` runs). */
	#user: UserPayload | null | undefined;
	readonly #abilities: Record<string, Ability<never[]>>;
	readonly #policies: Record<string, new () => BasePolicy>;
	readonly #scope: Scope;
	readonly #resolver: RightsResolver | undefined;
	#containerResolver: PolicyContainerResolver | undefined;
	readonly #emitter: BouncerEmitter | undefined;
	/** Memoized resolution — a Bouncer is fixed per `(user, scope)`, so resolve once (D3). */
	#resolved: Promise<EffectivePermissions> | undefined;

	constructor(
		user: UserPayload | (() => UserPayload | null) | null,
		abilities?: Record<string, Ability<never[]>>,
		policies?: Record<string, new () => BasePolicy>,
		context?: BouncerContext,
	) {
		this.#userOrResolver = user;
		this.#abilities = abilities ?? {};
		this.#policies = policies ?? {};
		this.#scope = context?.scope ?? "global";
		this.#resolver = context?.resolver;
		this.#containerResolver = context?.containerResolver;
		this.#emitter = context?.emitter;
	}

	/**
	 * Point the bouncer at an IoC resolver, so a policy's constructor
	 * dependencies are injected (AdonisJS `setContainerResolver`).
	 *
	 * The constructor takes one too; this is the setter AdonisJS exposes so the
	 * HTTP layer can hand over the REQUEST's resolver after the bouncer exists.
	 * Passing `undefined` clears it, and policies fall back to `new Policy()`.
	 */
	setContainerResolver(containerResolver?: PolicyContainerResolver): this {
		this.#containerResolver = containerResolver;
		return this;
	}

	/**
	 * Resolve the user, lazily invoking a resolver callback once and memoizing
	 * the result (Adonis `#getUser`). A plain `UserPayload | null` passes through.
	 */
	#getUser(): UserPayload | null {
		if (this.#user === undefined) {
			this.#user =
				typeof this.#userOrResolver === "function"
					? this.#userOrResolver()
					: this.#userOrResolver;
		}
		return this.#user;
	}

	/**
	 * Define an ability and open a chainable {@link AbilitiesBuilder} (Adonis
	 * `Bouncer.define`). Read `.abilities` off the returned builder to pass into a
	 * `new Bouncer(user, abilities)`.
	 */
	static define<Args extends unknown[]>(
		name: string,
		authorizer: (user: UserPayload, ...args: Args) => AuthorizerResponse,
		options?: AbilityOptions,
	): AbilitiesBuilder {
		return new AbilitiesBuilder().define(name, authorizer, options);
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
			const user = this.#getUser();
			this.#resolved =
				this.#resolver !== undefined && user !== null
					? this.#resolver.resolve(user, this.#scope)
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

	/**
	 * The checks a TEMPLATE performs, shared into the view per request so
	 * `@can('post.edit', post)` resolves them (AdonisJS shares the same pair
	 * under `bouncer`; it names the bag `edgeHelpers`, we do not borrow the
	 * engine's name).
	 *
	 * AdonisJS reads a dotted action as `policy.method` —
	 * `'PostPolicy.edit'` is `with('PostPolicy').allows('edit', …)`. Warden,
	 * however, keys its ABILITIES with dots (`'post.edit'`), so applying that
	 * split blindly would break every warden app.
	 *
	 * NAMED DEVIATION, strictly more permissive: a registered ability wins, and
	 * only an action with no matching ability falls through to the policy
	 * split. A migrated AdonisJS template resolves its policies exactly as
	 * before, and a warden app keeps its dotted abilities.
	 */
	readonly templateHelpers: {
		bouncer: {
			can(action: string, ...args: unknown[]): Promise<boolean>;
			cannot(action: string, ...args: unknown[]): Promise<boolean>;
		};
	} = {
		bouncer: {
			can: (action: string, ...args: unknown[]): Promise<boolean> => {
				const split = this.#splitAction(action);
				return split === undefined
					? this.allows(action, ...args)
					: this.with(split.policy).allows(split.method, ...args);
			},
			cannot: (action: string, ...args: unknown[]): Promise<boolean> => {
				const split = this.#splitAction(action);
				return split === undefined
					? this.denies(action, ...args)
					: this.with(split.policy).denies(split.method, ...args);
			},
		},
	};

	/** `policy.method` for a dotted action that names no registered ability;
	 * `undefined` when the action IS an ability (warden keys its own with dots). */
	#splitAction(action: string): { policy: string; method: string } | undefined {
		if (Object.hasOwn(this.#abilities, action)) return undefined;
		const dot = action.indexOf(".");
		if (dot <= 0 || dot === action.length - 1) return undefined;
		return { policy: action.slice(0, dot), method: action.slice(dot + 1) };
	}

	/** Open a policy for checks (D8 — fresh policy instance per check). */
	with(policy: (new () => BasePolicy) | string): PolicyAuthorizer {
		const factory =
			typeof policy === "string"
				? this.#resolvePolicyClass(policy)
				: () => this.#construct(policy);
		// The PolicyAuthorizer inherits the Bouncer's scope + the shared memoized
		// resolve so every policy check sees the active `(user, scope)` (AC1/AC3).
		return new PolicyAuthorizer(
			this.#getUser(),
			factory,
			this.#scope,
			() => this.#resolvePermissions(),
			this.#emitter,
			Bouncer.responseBuilder,
		);
	}

	/**
	 * Construct a policy instance via the container resolver when present (Adonis
	 * DI parity), else a plain `new Policy()` (D8 — a fresh instance per check).
	 */
	#construct(ctor: new () => BasePolicy): Promise<BasePolicy> {
		return this.#containerResolver !== undefined
			? this.#containerResolver.make(ctor)
			: Promise.resolve(new ctor());
	}

	/** Emit `authorization:finished` when an emitter is wired (no-op otherwise). */
	#emit(
		action: string,
		response: AuthorizationResponse,
		parameters: unknown[],
	): void {
		emitSafely(this.#emitter, "authorization:finished", {
			user: this.#getUser(),
			action,
			// What the check was ABOUT. AdonisJS carries it, and without it an
			// audit log can say "Ada was denied editPost" but never which post.
			parameters,
			response,
		});
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

	/** Resolves on allow; throws `AUTHORIZATION_FAILURE` on deny (D2). */
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
		const action = typeof ability === "string" ? ability : "(ability)";
		const response = await evaluate({
			user: this.#getUser(),
			action,
			allowGuest: resolved.allowGuest,
			run: (user) => resolved.execute(user, ...args),
			args,
			responseBuilder: Bouncer.responseBuilder,
		});
		this.#emit(action, response, args);
		return response;
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

	#resolvePolicyClass(name: string): () => Promise<BasePolicy> {
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
			return this.#construct(ctor);
		};
	}
}
