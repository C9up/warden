/**
 * Logging out ends the remember-me credential as well as the session: the
 * cookie is cleared and the stored token behind it deleted, so the next
 * request — with an empty session and the same cookie jar — is a guest.
 */
import { describe, expect, it } from "vitest";
import { Authenticator } from "../../src/Authenticator.js";
import { AuthManager, type UserPayload } from "../../src/AuthManager.js";
import type { WardenContext } from "../../src/middleware.js";
import {
	decodeTokenValue,
	MemoryRememberMeTokenDriver,
} from "../../src/RememberMeToken.js";
import {
	type SessionStore,
	SessionStrategy,
} from "../../src/strategies/SessionStrategy.js";

function defined<T>(value: T | null | undefined): T {
	if (value == null) throw new Error("expected a defined value");
	return value;
}

const u1: UserPayload = { id: "u1" };

function session(): SessionStore {
	const values = new Map<string, unknown>();
	return {
		get: (key) => values.get(key),
		put: (key, value) => {
			values.set(key, value);
		},
		forget: (key) => {
			values.delete(key);
		},
		regenerate: () => {},
	};
}

function browser() {
	const jar = new Map<string, string>();
	const cleared: string[] = [];
	return { jar, cleared };
}

function app(tokens = new MemoryRememberMeTokenDriver()) {
	const manager = new AuthManager({
		default: "web",
		guards: {
			web: new SessionStrategy({
				findUser: async (id) => (String(id) === "u1" ? u1 : null),
				rememberMeTokens: tokens,
				rememberMeAge: 3600,
			}),
		},
	});
	return { manager, tokens };
}

/** One request from `client`, against `manager`, with `store` as its session. */
function request(
	manager: AuthManager,
	client: ReturnType<typeof browser>,
	store: SessionStore,
): Authenticator {
	const ctx: WardenContext = {
		request: {
			headers: () => ({}),
			encryptedCookie: (name) => client.jar.get(name) ?? null,
		},
		response: {
			status: () => undefined,
			json: () => undefined,
			encryptedCookie: (name, value) => {
				client.jar.set(name, value);
			},
			clearCookie: (name) => {
				client.jar.delete(name);
				client.cleared.push(name);
			},
		},
		session: store,
	};
	return new Authenticator(ctx, manager);
}

describe("warden > logout ends the remember-me credential", () => {
	it("leaves the next request a guest, even with the same cookie jar", async () => {
		const { manager } = app();
		const client = browser();
		const signedIn = session();
		await request(manager, client, signedIn).use("web").login(u1, true);
		const cookie = defined(client.jar.get("remember_web"));

		await request(manager, client, signedIn).use("web").logout();

		// The browser comes back with an empty session and whatever it holds.
		const next = request(manager, client, session());
		expect(await next.check()).toBe(false);
		expect(next.user).toBeUndefined();

		// Even a copy of the cookie taken before the logout is dead.
		const thief = browser();
		thief.jar.set("remember_web", cookie);
		expect(await request(manager, thief, session()).check()).toBe(false);
	});

	it("clears the cookie and deletes the row behind it", async () => {
		const { manager, tokens } = app();
		const client = browser();
		const signedIn = session();
		await request(manager, client, signedIn).use("web").login(u1, true);
		const identifier = defined(
			decodeTokenValue(client.jar.get("remember_web")),
		).identifier;
		expect(await tokens.find(identifier)).not.toBeNull();

		await request(manager, client, signedIn).use("web").logout();

		expect(client.jar.has("remember_web")).toBe(false);
		expect(client.cleared).toContain("remember_web");
		expect(await tokens.find(identifier)).toBeNull();
	});

	it("deletes only this browser's token, not the user's other devices", async () => {
		const { manager } = app();
		const laptop = browser();
		const phone = browser();
		const laptopSession = session();
		await request(manager, laptop, laptopSession).use("web").login(u1, true);
		await request(manager, phone, session()).use("web").login(u1, true);

		await request(manager, laptop, laptopSession).use("web").logout();

		expect(await request(manager, phone, session()).check()).toBe(true);
	});

	it("logs out as before when no cookie is held", async () => {
		const { manager } = app();
		const client = browser();
		const signedIn = session();
		await request(manager, client, signedIn).use("web").login(u1);

		const out = request(manager, client, signedIn);
		await out.use("web").logout();

		expect(out.use("web").isLoggedOut).toBe(true);
		expect(signedIn.get("auth_user_id")).toBeUndefined();
	});

	it("clears the cookie and ends the session even when the token store fails", async () => {
		const tokens = new MemoryRememberMeTokenDriver();
		const { manager } = app(tokens);
		const client = browser();
		const signedIn = session();
		await request(manager, client, signedIn).use("web").login(u1, true);
		tokens.delete = async () => {
			throw new Error("token store is down");
		};

		await expect(
			request(manager, client, signedIn).use("web").logout(),
		).rejects.toThrow(/token store is down/);

		// The browser no longer holds the credential, and the session is over.
		expect(client.jar.has("remember_web")).toBe(false);
		expect(signedIn.get("auth_user_id")).toBeUndefined();
	});
});
