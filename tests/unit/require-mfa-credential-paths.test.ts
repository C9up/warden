/**
 * `@RequireMfa` reads `user.mfa`, and that flag must only ever be the step-up of
 * the credential that authenticated THIS request.
 *
 * A users table commonly carries an `mfa` column meaning "MFA is enabled on the
 * account". When a guard handed `findUser`'s row to the request untouched, that
 * column alone unlocked every `@RequireMfa` route: an access token, a Basic
 * credential, or a stolen remember-me cookie replayed without a session went
 * straight through, with no step-up ever performed. Each test below is that
 * attack, and each must end in 403 E_WARDEN_MFA_REQUIRED.
 */
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import {
	AccessTokensProvider,
	MemoryAccessTokenStore,
} from "../../src/AccessToken.js";
import { AuthManager, type UserPayload } from "../../src/AuthManager.js";
import { Guard, RequireMfa } from "../../src/Guard.js";
import {
	wardenMiddleware as unhandledWardenMiddleware,
	type WardenContext,
} from "../../src/middleware.js";
import { MemoryRememberMeTokenDriver } from "../../src/RememberMeToken.js";
import { ApiKeyStrategy } from "../../src/strategies/ApiKeyStrategy.js";
import { BasicAuthStrategy } from "../../src/strategies/BasicAuthStrategy.js";
import {
	type SessionStore,
	SessionStrategy,
} from "../../src/strategies/SessionStrategy.js";
import { withExceptionHandler } from "./support/exceptionHandler.js";

/** The middleware as the host runs it, behind its exception handler. */
const wardenMiddleware = withExceptionHandler(unhandledWardenMiddleware);

/** The row an application's users table hands back: MFA ENABLED, not performed. */
const mfaEnabledRow = async (id: string | number): Promise<UserPayload> => ({
	id: String(id),
	mfa: true,
});

class TransferController {
	@Guard("api")
	@RequireMfa()
	async viaToken() {}

	@Guard("basic")
	@RequireMfa()
	async viaBasic() {}

	@Guard("web")
	@RequireMfa()
	async viaSession() {}
}

function memorySession(): SessionStore {
	const store = new Map<string, unknown>();
	return {
		get: (key) => store.get(key),
		put: (key, value) => {
			store.set(key, value);
		},
		forget: (key) => {
			store.delete(key);
		},
		regenerate: () => {},
	};
}

function setup() {
	const tokens = new AccessTokensProvider({
		store: new MemoryAccessTokenStore(),
	});
	const rememberMeTokens = new MemoryRememberMeTokenDriver();
	const web = new SessionStrategy({
		findUser: mfaEnabledRow,
		rememberMeTokens,
	});
	const manager = new AuthManager({
		default: "web",
		guards: {
			web,
			api: new ApiKeyStrategy({ tokens, findUser: mfaEnabledRow }),
			basic: new BasicAuthStrategy({
				verifyCredentials: async (uid, password) =>
					uid === "u" && password === "p" ? { id: "u1", mfa: true } : null,
			}),
		},
	});
	return { manager, tokens, web };
}

async function run(
	manager: AuthManager,
	action: keyof TransferController,
	request: {
		headers?: Record<string, string>;
		cookies?: Record<string, string>;
	},
) {
	const response: { status?: number; body?: unknown } = {};
	let reached = false;
	const cookies = request.cookies ?? {};
	const ctx: WardenContext = {
		request: {
			headers: () => request.headers ?? {},
			encryptedCookie: (name) => cookies[name] ?? null,
		},
		response: {
			status(code) {
				response.status = code;
			},
			json(data) {
				response.body = data;
			},
			encryptedCookie: () => undefined,
			clearCookie: () => undefined,
		},
		session: memorySession(),
		route: { controller: TransferController.prototype, action },
		containerResolver: {
			async make(token) {
				if (token === AuthManager) return manager;
				throw new Error(`No binding for ${String(token)}`);
			},
		},
	};
	await wardenMiddleware(ctx, () => {
		reached = true;
	});
	return { response, reached, ctx };
}

const mfaRequired = {
	error: { code: "E_WARDEN_MFA_REQUIRED", message: expect.any(String) },
};

describe("warden > @RequireMfa ignores findUser's own `mfa` field", () => {
	it("refuses an access token whose user row says mfa: true", async () => {
		const { manager, tokens } = setup();
		const token = await tokens.create({ id: "u1" }, ["*"]);
		const value = token.value?.release() ?? "";

		const { response, reached } = await run(manager, "viaToken", {
			headers: { authorization: `Bearer ${value}` },
		});

		expect(reached).toBe(false);
		expect(response.status).toBe(403);
		expect(response.body).toEqual(mfaRequired);
	});

	it("refuses a Basic credential whose user says mfa: true", async () => {
		const { manager } = setup();
		const header = `Basic ${Buffer.from("u:p").toString("base64")}`;

		const { response, reached } = await run(manager, "viaBasic", {
			headers: { authorization: header },
		});

		expect(reached).toBe(false);
		expect(response.status).toBe(403);
		expect(response.body).toEqual(mfaRequired);
	});

	it("refuses a remember-me cookie replayed without a session", async () => {
		const { manager, web } = setup();
		const cookie = (await web.issueRememberMeToken({ id: "u1" })) ?? "";

		const { response, reached, ctx } = await run(manager, "viaSession", {
			cookies: { [web.rememberMeCookieName]: cookie },
		});

		// The cookie did authenticate — the user is signed back in …
		expect(ctx.auth?.user?.id).toBe("u1");
		// … but a revived session has not stepped up.
		expect(ctx.auth?.user?.mfa).toBe(false);
		expect(reached).toBe(false);
		expect(response.status).toBe(403);
		expect(response.body).toEqual(mfaRequired);
	});

	it("still lets a session that stepped up through", async () => {
		const { web } = setup();
		const session = memorySession();
		await web.login({ id: "u1" }, session);
		web.markMfaVerified(session);
		const verified = await web.verifyWithContext("", { session });

		expect(verified.user?.mfa).toBe(true);
	});

	it("leaves the strategies' own results at mfa: false", async () => {
		const { tokens, web } = setup();
		const api = new ApiKeyStrategy({ tokens, findUser: mfaEnabledRow });
		const token = await tokens.create({ id: "u1" }, ["*"]);
		const viaToken = await api.verify(token.value?.release() ?? "");
		expect(viaToken.user?.mfa).toBe(false);

		const basic = new BasicAuthStrategy({
			verifyCredentials: async () => ({ id: "u1", mfa: true }),
		});
		expect(
			(await basic.authenticate({ uid: "u", password: "p" })).user?.mfa,
		).toBe(false);

		const cookie = await web.issueRememberMeToken({ id: "u1" });
		const revived = await web.authenticateViaRememberMeToken(cookie);
		expect(revived?.user.mfa).toBe(false);
	});
});
