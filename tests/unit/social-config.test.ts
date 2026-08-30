/**
 * `config.auth.socials` — the declarative half of social sign-in.
 *
 * `FirstContactManager` was exported and never registered: every application
 * had to build it, register each driver by hand, and put it somewhere its
 * controllers could reach. The config section is what removes that.
 */
import "reflect-metadata";
import { describe, expect, it, vi } from "vitest";
import type { WardenConfig } from "../../src/config.js";
import { socials } from "../../src/config.js";
import { GitHubDriver } from "../../src/firstcontact/drivers/GitHubDriver.js";
import { GoogleDriver } from "../../src/firstcontact/drivers/GoogleDriver.js";
import { FirstContactManager } from "../../src/firstcontact/FirstContactManager.js";
import type { FirstContactDriver } from "../../src/firstcontact/types.js";
import WardenProvider, {
	type WardenAppContext,
} from "../../src/WardenProvider.js";

function makeApp(authConfig: WardenConfig): {
	registry: Map<unknown, () => unknown>;
	app: WardenAppContext;
} {
	const registry = new Map<unknown, () => unknown>();
	const app: WardenAppContext = {
		container: {
			singleton(token: unknown, factory: () => unknown) {
				registry.set(token, factory);
			},
			async resolve(token: unknown) {
				return registry.get(token)?.();
			},
		},
		config: {
			get<T = unknown>(key: string): T | undefined {
				return key === "auth" ? (authConfig as T) : undefined;
			},
		},
	};
	return { registry, app };
}

const credentials = {
	clientId: "id",
	clientSecret: "secret",
	callbackUrl: "https://acme.test/callback",
};

const jwt: NonNullable<WardenConfig["jwt"]> = {
	secret: "x".repeat(32),
	async findUser() {
		return null;
	},
	async verifyCredentials() {
		return null;
	},
};

describe("warden > social sign-in config", () => {
	it("registers the manager under its class and the `socials` alias", async () => {
		const { registry, app } = makeApp({
			jwt,
			socials: { google: socials.google(credentials) },
		});

		new WardenProvider(app).register();

		const byClass = registry.get(FirstContactManager)?.();
		expect(byClass).toBeInstanceOf(FirstContactManager);
		// The string alias is what a consumer that cannot import warden resolves.
		expect(registry.get("socials")?.()).toBe(byClass);
	});

	it("keys each driver by the name the config chose, not by its kind", () => {
		const { registry, app } = makeApp({
			jwt,
			socials: {
				staff: socials.google(credentials),
				customers: socials.google({ ...credentials, clientId: "other" }),
			},
		});

		new WardenProvider(app).register();
		const manager = registry.get(
			FirstContactManager,
		)?.() as FirstContactManager;

		// Two entries, same driver, different credentials — which is why the key
		// is the caller's and `use()` asks for it.
		expect(manager.registeredDrivers).toEqual(["staff", "customers"]);
		expect(manager.use("staff")).not.toBe(manager.use("customers"));
	});

	it("takes a driver given directly", () => {
		const driver: FirstContactDriver = {
			redirectUrl: () => "https://acme.test/go",
			callback: async () => {
				throw new Error("not used");
			},
		};
		const { registry, app } = makeApp({ jwt, socials: { custom: driver } });

		new WardenProvider(app).register();
		const manager = registry.get(
			FirstContactManager,
		)?.() as FirstContactManager;

		expect(manager.use("custom")).toBe(driver);
	});

	it("registers nothing when no provider is declared", () => {
		const { registry, app } = makeApp({ jwt });

		new WardenProvider(app).register();

		// Resolving a manager an application never configured should fail at the
		// container, not hand back an empty one that throws on first use.
		expect(registry.has(FirstContactManager)).toBe(false);
		expect(registry.has("socials")).toBe(false);
	});

	it("builds each driver only when the provider registers", () => {
		const built = vi.fn(() => socials.github(credentials)());
		const { app } = makeApp({ jwt, socials: { github: built } });

		expect(built).not.toHaveBeenCalled();
		new WardenProvider(app).register();
		expect(built).toHaveBeenCalledTimes(1);
	});

	it("builds the driver each helper names", () => {
		expect(socials.google(credentials)()).toBeInstanceOf(GoogleDriver);
		expect(socials.github(credentials)()).toBeInstanceOf(GitHubDriver);
	});
});
