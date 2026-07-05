import "reflect-metadata";
import { describe, expect, it } from "vitest";
import { AuthManager, type UserPayload } from "../../src/AuthManager.js";
import type { WardenConfig } from "../../src/config.js";
import { MemoryRightsStore } from "../../src/rights/MemoryRightsStore.js";
import { RightsResolver } from "../../src/rights/RightsResolver.js";
import { ApiKeyStrategy } from "../../src/strategies/ApiKeyStrategy.js";
import { JwtStrategy } from "../../src/strategies/JwtStrategy.js";
import { SessionStrategy } from "../../src/strategies/SessionStrategy.js";
import WardenProvider, {
	type WardenAppContext,
} from "../../src/WardenProvider.js";

type SingletonFactory = () => unknown;
type Token = unknown;

interface FakeContainer {
	singleton(token: Token, factory: SingletonFactory): void;
	resolve(token: Token): unknown;
	registry: Map<Token, SingletonFactory>;
	instances: Map<Token, unknown>;
}

function makeFakeContainer(): FakeContainer {
	const registry = new Map<Token, SingletonFactory>();
	const instances = new Map<Token, unknown>();
	return {
		registry,
		instances,
		singleton(token, factory) {
			registry.set(token, factory);
		},
		resolve(token) {
			if (instances.has(token)) return instances.get(token);
			const factory = registry.get(token);
			if (!factory) throw new Error("not registered");
			const value = factory();
			instances.set(token, value);
			return value;
		},
	};
}

function makeFakeApp(authConfig: WardenConfig | undefined): {
	container: FakeContainer;
	app: WardenAppContext;
} {
	const container = makeFakeContainer();
	const app: WardenAppContext = {
		container,
		config: {
			get<T = unknown>(key: string): T | undefined {
				if (key === "auth" && authConfig) return authConfig as T;
				return undefined;
			},
		},
	};
	return { container, app };
}

const validJwtConfig: NonNullable<WardenConfig["jwt"]> = {
	secret: "x".repeat(32),
	expiresInSeconds: 3600,
	async findUser() {
		return null;
	},
	async verifyCredentials() {
		return null;
	},
};

describe("warden > WardenProvider", () => {
	it("THROWS WARDEN_NO_AUTH_CONFIG at register-time when no jwt config is provided", () => {
		// Was: silently registered an empty AuthManager and the first
		// protected request crashed deep in the middleware loop. Now boot
		// fails fast with an actionable error pointing at reamrc.ts.
		const { app } = makeFakeApp({ defaultStrategy: "jwt" });
		expect(() => new WardenProvider(app).register()).toThrow(
			/WARDEN_NO_AUTH_CONFIG|no authentication guards configured/,
		);
	});

	it("registers JwtStrategy + AuthManager when jwt config is provided", () => {
		const { container, app } = makeFakeApp({
			defaultStrategy: "jwt",
			jwt: validJwtConfig,
		});
		new WardenProvider(app).register();

		expect(container.registry.has(JwtStrategy)).toBe(true);
		expect(container.registry.has(AuthManager)).toBe(true);

		const jwt = container.resolve(JwtStrategy);
		expect(jwt).toBeInstanceOf(JwtStrategy);

		const manager = container.resolve(AuthManager);
		expect(manager).toBeInstanceOf(AuthManager);
		if (manager instanceof AuthManager) {
			expect(() => manager.getStrategy("jwt")).not.toThrow();
		}
	});

	it("binds the AuthManager under the 'auth' string alias (consumers resolve by name)", () => {
		// @c9up/station resolves container.resolve("auth") to gate its admin
		// routes — it can't import the AuthManager class (stays warden-
		// agnostic). Without this alias the resolve threw and Station's auth
		// gate silently fell back to open mode. Mirrors events→"bus" /
		// rosetta→"i18n".
		const { container, app } = makeFakeApp({
			defaultStrategy: "jwt",
			jwt: validJwtConfig,
		});
		new WardenProvider(app).register();

		expect(container.registry.has("auth")).toBe(true);
		const viaAlias = container.resolve("auth");
		const viaClass = container.resolve(AuthManager);
		expect(viaAlias).toBeInstanceOf(AuthManager);
		expect(viaAlias).toBe(viaClass);
	});

	it("falls back to defaultStrategy='jwt' when config omits it", () => {
		const { container, app } = makeFakeApp({ jwt: validJwtConfig });
		new WardenProvider(app).register();

		const manager = container.resolve(AuthManager);
		expect(manager).toBeInstanceOf(AuthManager);
		if (manager instanceof AuthManager) {
			expect(() => manager.getStrategy("jwt")).not.toThrow();
		}
	});

	it("registers MemoryRightsStore + RightsResolver singletons (Epic 56)", () => {
		const { container, app } = makeFakeApp({
			defaultStrategy: "jwt",
			jwt: validJwtConfig,
		});
		new WardenProvider(app).register();

		expect(container.registry.has(MemoryRightsStore)).toBe(true);
		expect(container.registry.has(RightsResolver)).toBe(true);
		expect(container.resolve(MemoryRightsStore)).toBeInstanceOf(
			MemoryRightsStore,
		);
		expect(container.resolve(RightsResolver)).toBeInstanceOf(RightsResolver);
	});

	it("resolves an AuthManager whose hasPermission consults the registered resolver", async () => {
		const { container, app } = makeFakeApp({
			defaultStrategy: "jwt",
			jwt: validJwtConfig,
		});
		new WardenProvider(app).register();

		// Seed the registered store (resolvable by class so an app seeds at boot),
		// then resolve the AuthManager — it must read the SAME backing store.
		const store = container.resolve(MemoryRightsStore);
		expect(store).toBeInstanceOf(MemoryRightsStore);
		if (!(store instanceof MemoryRightsStore)) return;
		store.defineRole("editor", ["post.edit"]).assignRole("u1", "editor");

		const manager = container.resolve(AuthManager);
		expect(manager).toBeInstanceOf(AuthManager);
		if (!(manager instanceof AuthManager)) return;
		const user: UserPayload = { id: "u1" };
		expect(await manager.hasPermission(user, "post.edit")).toBe(true);
		expect(await manager.hasPermission(user, "post.delete")).toBe(false);
	});

	it("honours a custom config.auth.rights.store (AD5 — pluggable store)", async () => {
		const custom = new MemoryRightsStore().grant("u1", "from.custom.store");
		const { container, app } = makeFakeApp({
			defaultStrategy: "jwt",
			jwt: validJwtConfig,
			rights: { store: custom },
		});
		new WardenProvider(app).register();

		const manager = container.resolve(AuthManager);
		expect(manager).toBeInstanceOf(AuthManager);
		if (!(manager instanceof AuthManager)) return;
		const user: UserPayload = { id: "u1" };
		// The grant lives ONLY in the supplied store, proving it backs the resolver.
		expect(await manager.hasPermission(user, "from.custom.store")).toBe(true);
	});

	it("registers SessionStrategy under 'session' when config.session is provided", () => {
		const { container, app } = makeFakeApp({
			jwt: validJwtConfig,
			session: {
				async findUser() {
					return null;
				},
			},
		});
		new WardenProvider(app).register();

		expect(container.registry.has(SessionStrategy)).toBe(true);
		const manager = container.resolve(AuthManager);
		if (manager instanceof AuthManager) {
			// Previously @Guard('session') crashed with STRATEGY_NOT_FOUND.
			expect(() => manager.getStrategy("session")).not.toThrow();
		}
	});

	it("registers ApiKeyStrategy under 'api-key' when config.apiKey is provided", () => {
		const { container, app } = makeFakeApp({
			jwt: validJwtConfig,
			apiKey: {
				async findByKey() {
					return null;
				},
			},
		});
		new WardenProvider(app).register();

		expect(container.registry.has(ApiKeyStrategy)).toBe(true);
		const manager = container.resolve(AuthManager);
		if (manager instanceof AuthManager) {
			expect(() => manager.getStrategy("api-key")).not.toThrow();
		}
	});

	it("boots a session-only app (no jwt) and defaults to the 'session' strategy", () => {
		const { container, app } = makeFakeApp({
			session: {
				async findUser() {
					return null;
				},
			},
		});
		expect(() => new WardenProvider(app).register()).not.toThrow();

		const manager = container.resolve(AuthManager);
		expect(manager).toBeInstanceOf(AuthManager);
		if (manager instanceof AuthManager) {
			expect(() => manager.getStrategy()).not.toThrow(); // default → session
			expect(() => manager.getStrategy("jwt")).toThrow(); // jwt not configured
		}
	});

	it("THROWS WARDEN_NO_AUTH_CONFIG when 'auth' config is entirely absent", () => {
		// Same fail-fast guard from a different angle — `config.get('auth')`
		// returns undefined (no `config.warden.auth` block at all).
		const { app } = makeFakeApp(undefined);
		expect(() => new WardenProvider(app).register()).toThrow(
			/WARDEN_NO_AUTH_CONFIG|no authentication guards configured/,
		);
	});
});
