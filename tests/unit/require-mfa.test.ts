/**
 * @RequireMfa middleware enforcement + decorator metadata. An authenticated
 * user must carry a truthy `mfa` claim to pass a route decorated with
 * @RequireMfa; otherwise the middleware returns 403 MFA_REQUIRED.
 */
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import {
	AuthManager,
	type AuthStrategy,
	type UserPayload,
} from "../../src/AuthManager.js";
import { Guard, getRequireMfaMetadata, RequireMfa } from "../../src/Guard.js";
import { type WardenContext, wardenMiddleware } from "../../src/middleware.js";

class SensitiveController {
	@Guard("jwt")
	@RequireMfa()
	async transfer() {
		return "ok";
	}
}

function managerReturning(user: UserPayload): AuthManager {
	const strategy: AuthStrategy = {
		name: "jwt",
		async authenticate() {
			return { authenticated: false, error: "n/a" };
		},
		async verify() {
			return { authenticated: true, user };
		},
	};
	return new AuthManager({
		defaultStrategy: "jwt",
		strategies: { jwt: strategy },
	});
}

function run(manager: AuthManager) {
	const response: { status?: number; body?: unknown } = {};
	const state = { nextCalled: false };
	const ctx: WardenContext = {
		request: {
			method: "POST",
			url: "/api/transfer",
			headers: { authorization: "Bearer tok" },
		},
		response: {
			status(code) {
				response.status = code;
			},
			json(data) {
				response.body = data;
			},
		},
		container: {
			resolve(token) {
				if (token === AuthManager) return manager;
				throw new Error(`unexpected token: ${String(token)}`);
			},
		},
		session: undefined,
		route: { controller: SensitiveController.prototype, action: "transfer" },
	};
	return {
		exec: () =>
			wardenMiddleware(ctx, () => {
				state.nextCalled = true;
			}),
		response,
		state,
	};
}

describe("warden > @RequireMfa", () => {
	it("marks the route via decorator metadata", () => {
		expect(
			getRequireMfaMetadata(SensitiveController.prototype, "transfer"),
		).toBe(true);
		expect(
			getRequireMfaMetadata(SensitiveController.prototype, "missing"),
		).toBe(false);
	});

	it("rejects an authenticated user without the mfa claim (403 MFA_REQUIRED)", async () => {
		const h = run(managerReturning({ id: "u1" }));
		await h.exec();
		expect(h.response.status).toBe(403);
		expect(h.response.body).toEqual({
			error: { code: "MFA_REQUIRED", message: expect.any(String) },
		});
		expect(h.state.nextCalled).toBe(false);
	});

	it("allows a user that completed MFA (mfa: true)", async () => {
		const h = run(managerReturning({ id: "u1", mfa: true }));
		await h.exec();
		expect(h.response.status).toBeUndefined();
		expect(h.state.nextCalled).toBe(true);
	});
});
