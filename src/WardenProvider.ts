import { AuthManager } from "./AuthManager.js";
import type { WardenConfig } from "./config.js";
import { WardenError } from "./errors.js";
import { MfaManager } from "./mfa/MfaManager.js";
import { MemoryRightsStore } from "./rights/MemoryRightsStore.js";
import { RightsResolver } from "./rights/RightsResolver.js";
import { setAuth } from "./services/main.js";
import { JwtStrategy } from "./strategies/JwtStrategy.js";

interface WardenContainer {
	singleton(token: unknown, factory: () => unknown): void;
	resolve(token: unknown): unknown;
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
		if (!config?.jwt) {
			throw new WardenError(
				"WARDEN_NO_AUTH_CONFIG",
				`@c9up/warden: no authentication strategies configured. Set config.warden.auth.jwt (or another strategy) in your reamrc.ts before registering WardenProvider.`,
			);
		}

		const jwt = new JwtStrategy(config.jwt);
		this.app.container.singleton(JwtStrategy, () => jwt);

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

		this.app.container.singleton(AuthManager, () => {
			const strategies: Record<string, JwtStrategy> = { jwt };
			return new AuthManager({
				defaultStrategy: config.defaultStrategy ?? "jwt",
				strategies,
				rights: rightsResolver,
			});
		});
		// String alias so consumers that can't import the AuthManager class
		// (e.g. @c9up/station, which stays agnostic of warden) can resolve
		// it by name. Mirrors the convention other providers follow
		// (events → "bus", rosetta → "i18n"). Without this, Station's
		// `container.resolve("auth")` threw and its admin auth gate
		// silently fell back to open-mode.
		this.app.container.singleton("auth", () =>
			this.app.container.resolve(AuthManager),
		);

		// MFA (optional): the app builds an MfaManager with its persistent stores
		// + providers and passes it via config.mfa. Registered by class and under
		// the "mfa" string alias (same convention as "auth") so controllers and
		// agnostic consumers can resolve it.
		const mfa = config.mfa?.manager;
		if (mfa) {
			this.app.container.singleton(MfaManager, () => mfa);
			this.app.container.singleton("mfa", () => mfa);
		}
	}

	async boot() {
		setAuth(this.app.container.resolve(AuthManager) as AuthManager);
	}
}
