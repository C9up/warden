import "./augmentations.js";
import { AuthManager, type AuthStrategy } from "./AuthManager.js";
import type { WardenConfig } from "./config.js";
import { WardenError } from "./errors.js";
import { MfaManager } from "./mfa/MfaManager.js";
import type { BouncerRegistry } from "./middleware.js";
import { MemoryRightsStore } from "./rights/MemoryRightsStore.js";
import { RightsResolver } from "./rights/RightsResolver.js";
import { setAuth } from "./services/main.js";
import { ApiKeyStrategy } from "./strategies/ApiKeyStrategy.js";
import { JwtStrategy } from "./strategies/JwtStrategy.js";
import { SessionStrategy } from "./strategies/SessionStrategy.js";

interface WardenContainer {
	singleton(token: unknown, factory: () => unknown): void;
	resolve(token: unknown): Promise<unknown>;
}

interface WardenConfigStore {
	get<T = unknown>(key: string): T | undefined;
}

export interface WardenAppContext {
	container: WardenContainer;
	config: WardenConfigStore;
}

export default class WardenProvider {
	constructor(protected app: WardenAppContext) {}

	register() {
		// Register JwtStrategy first so it's available before AuthManager resolves.
		// The previous version nested the JwtStrategy registration inside the
		// AuthManager factory — that was order-dependent and fragile.
		const config = this.app.config.get<WardenConfig>("auth");

		// Fail-fast at register-time so the operator gets a clear actionable
		// error during boot instead of an opaque runtime crash on the first
		// protected request. Previously, missing `config.auth` produced an
		// AuthManager with `strategies: {}` and `defaultStrategy: 'jwt'`,
		// passing the (then-permissive) constructor and erroring deep in the
		// middleware loop.
		const hasGuards = config?.guards && Object.keys(config.guards).length > 0;
		if (!hasGuards && !config?.jwt && !config?.session && !config?.apiKey) {
			throw new WardenError(
				"E_WARDEN_NO_AUTH_CONFIG",
				`@c9up/warden: no authentication guards configured. Set config.warden.auth.guards (AdonisJS form) or at least one of .jwt / .session / .apiKey in your reamrc.ts before registering WardenProvider.`,
			);
		}

		// Build the guard table. Two accepted forms:
		//  - AdonisJS: `config.guards` (name → AuthStrategy, via *Guard() factories).
		//  - Legacy driver-keyed: `config.jwt` / `.session` / `.apiKey`.
		// Each strategy is also exposed by its class token (so apps can resolve a
		// specific one). The `revoke()` blacklist flows through `config.jwt.blacklist`.
		const strategies: Record<string, AuthStrategy> = {};

		if (hasGuards && config.guards) {
			for (const [name, strategy] of Object.entries(config.guards)) {
				strategies[name] = strategy;
				// Expose recognised driver instances by their class token too.
				if (strategy instanceof JwtStrategy) {
					this.app.container.singleton(JwtStrategy, () => strategy);
				} else if (strategy instanceof SessionStrategy) {
					this.app.container.singleton(SessionStrategy, () => strategy);
				} else if (strategy instanceof ApiKeyStrategy) {
					this.app.container.singleton(ApiKeyStrategy, () => strategy);
				}
			}
		} else {
			if (config.jwt) {
				const jwt = new JwtStrategy(config.jwt);
				this.app.container.singleton(JwtStrategy, () => jwt);
				strategies.jwt = jwt;
			}
			if (config.session) {
				const session = new SessionStrategy(config.session);
				this.app.container.singleton(SessionStrategy, () => session);
				strategies.session = session;
			}
			if (config.apiKey) {
				const apiKey = new ApiKeyStrategy(config.apiKey);
				this.app.container.singleton(ApiKeyStrategy, () => apiKey);
				// AdonisJS names this guard driver "access_tokens"; keep "api-key"
				// as an accepted alias so existing `@Guard('api-key')` routes work.
				strategies.access_tokens = apiKey;
				strategies["api-key"] = apiKey;
			}
		}

		// Login route (session-guard HTML redirect target) — resolved by the
		// enforcing middleware via the "warden:loginRoute" token. Registered even
		// when undefined so the lookup is a clean resolve, not a throw.
		const loginRoute = config.loginRoute;
		this.app.container.singleton("warden:loginRoute", () => loginRoute);

		// Rights layer (Epic 56): one resolver singleton backs BOTH the coarse
		// RBAC helpers (injected into AuthManager below) and — once 56.6 lands —
		// the Bouncer construction, so a coarse question and a policy question
		// resolve through the SAME instance (single unification point, AC-E3).
		// The store defaults to an in-memory driver and is exposed (by class)
		// so an app can seed roles/grants at boot, or supply its own via
		// `config.auth.rights.store` (AD5).
		const rightsStore = config.rights?.store ?? new MemoryRightsStore();
		const rightsResolver = new RightsResolver(rightsStore);
		this.app.container.singleton(RightsResolver, () => rightsResolver);
		if (rightsStore instanceof MemoryRightsStore) {
			this.app.container.singleton(MemoryRightsStore, () => rightsStore);
		}

		// Bouncer registry (Epic 56.6): the abilities/policies/scope-resolver the
		// per-request `initializeBouncer` middleware builds each `ctx.bouncer`
		// from. Registered (even when empty) under a string token so the agnostic
		// middleware resolves it by name, mirroring the "auth" alias above.
		const bouncerRegistry: BouncerRegistry = {
			abilities: config.abilities ?? {},
			policies: config.policies ?? {},
			resolveScope: config.resolveScope,
		};
		this.app.container.singleton("bouncer:registry", () => bouncerRegistry);

		// Default to the configured guard (AdonisJS `default`, then legacy
		// `defaultStrategy`), else the first one registered.
		const defaultGuard =
			config.default ?? config.defaultStrategy ?? Object.keys(strategies)[0];
		this.app.container.singleton(AuthManager, () => {
			return new AuthManager({
				default: defaultGuard,
				guards: strategies,
				rights: rightsResolver,
			});
		});
		// String alias so consumers that can't import the AuthManager class
		// (e.g. @c9up/station, which stays agnostic of warden) can resolve
		// it by name. Mirrors the convention other providers follow
		// (events → "bus", rosetta → "i18n"). Without this, Station's
		// `container.resolve("auth")` threw and its admin auth gate
		// silently fell back to open-mode.
		// Namespaced by the package that owns it, the way upstream namespaces
		// `lucid.db`, `auth.manager` and `drive.manager` by theirs. The bare
		// token stays bound beside it: it is what every existing
		// `container.make(...)` asks for, and a token is not worth breaking an
		// application over.
		// The host container is duck-typed here, so the factory answers
		// `unknown`; what `container.make('warden.auth')` hands back is typed by
		// the augmentation, not by this call.
		const auth = (): unknown => this.app.container.resolve(AuthManager);
		this.app.container.singleton("warden.auth", auth);
		this.app.container.singleton("auth", auth);

		// MFA (optional): the app builds an MfaManager with its persistent stores
		// + providers and passes it via config.mfa. Registered by class and under
		// the "mfa" string alias (same convention as "auth") so controllers and
		// agnostic consumers can resolve it.
		const mfa = config.mfa?.manager;
		if (mfa) {
			this.app.container.singleton(MfaManager, () => mfa);
			this.app.container.singleton("warden.mfa", () => mfa);
			this.app.container.singleton("mfa", () => mfa);
		}
	}

	async boot() {
		const manager = await this.app.container.resolve(AuthManager);
		if (manager instanceof AuthManager) setAuth(manager);
		await this.#registerTemplateTags();
	}

	/**
	 * Publish `@can` / `@cannot` to the template engine, as AdonisJS's bouncer
	 * does. A migrated template keeps `@can('PostPolicy.edit', post) … @endcan`
	 * unchanged.
	 *
	 * Both are BLOCK tags and both AWAIT — the check returns a promise — so they
	 * render on the async path and raise on a synchronous one, matching upstream
	 * (which emits `await bouncer.can(...)`). The checks themselves come from
	 * `ctx.bouncer.templateHelpers`, shared into the view per request.
	 *
	 * Resolved through the container: warden must not depend on the engine, and
	 * an app with no template layer simply skips this.
	 */
	async #registerTemplateTags(): Promise<void> {
		const engine = await this.#resolveTemplateEngine();
		if (engine === undefined) return;
		for (const tagName of ["can", "cannot"] as const) {
			engine.registerTag({
				tagName,
				block: true,
				seekable: true,
				async compile(_parser, buffer, token) {
					// The shared bag lives in the render scope under `bouncer`.
					const bouncer = token.evaluate(
						"typeof bouncer === 'undefined' ? undefined : bouncer",
					);
					const check = Reflect.get(Object(bouncer), tagName);
					if (typeof check !== "function") {
						// No bouncer on this request: deny rather than render an
						// unguarded body.
						return;
					}
					const args = token.evaluate(`[${token.properties.jsArg}]`);
					const allowed = await check.apply(
						bouncer,
						Array.isArray(args) ? args : [],
					);
					if (allowed === true) buffer.writeRaw(await token.renderBody());
				},
			});
		}
	}

	/** The template engine, if the host installed one. */
	async #resolveTemplateEngine(): Promise<TemplateEngineLike | undefined> {
		for (const token of ["inker", "view"]) {
			try {
				const binding: unknown = await this.app.container.resolve(token);
				for (const candidate of [
					binding,
					Reflect.get(Object(binding), "_templates"),
				]) {
					if (
						typeof candidate === "object" &&
						candidate !== null &&
						typeof Reflect.get(candidate, "registerTag") === "function"
					) {
						return {
							registerTag: Reflect.get(candidate, "registerTag").bind(
								candidate,
							),
						};
					}
				}
			} catch {
				// A host without a template layer is not an error.
			}
		}
		return undefined;
	}
}

/** The only surface warden needs of a template engine. */
interface TemplateEngineLike {
	registerTag(tag: {
		tagName: string;
		block: boolean;
		seekable: boolean;
		compile(
			parser: unknown,
			buffer: { writeRaw(text: string): void },
			token: {
				properties: { jsArg: string };
				renderBody(): string | Promise<string>;
				evaluate(expression: string): unknown;
			},
		): void | Promise<void>;
	}): void;
}
