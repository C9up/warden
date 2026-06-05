/**
 * ApiKeyStrategy — verify() lookup, scope→permission merge, and the
 * unsupported credential path. Was at 50% function coverage.
 */
import { describe, expect, it } from "vitest";
import type { UserPayload } from "../../src/AuthManager.js";
import { ApiKeyStrategy } from "../../src/strategies/ApiKeyStrategy.js";

const user: UserPayload = {
	id: "u1",
	email: "k@c9up.com",
	permissions: ["read"],
};

describe("warden > ApiKeyStrategy", () => {
	it("defaults the header to x-api-key and honours a custom one", () => {
		expect(new ApiKeyStrategy({ findByKey: async () => null }).headerName).toBe(
			"x-api-key",
		);
		expect(
			new ApiKeyStrategy({ headerName: "x-token", findByKey: async () => null })
				.headerName,
		).toBe("x-token");
	});

	it("rejects credential-based auth (must use verify with the key)", async () => {
		const s = new ApiKeyStrategy({ findByKey: async () => null });
		await expect(s.authenticate({ email: "a", password: "b" })).rejects.toThrow(
			/does not support credential-based auth/,
		);
	});

	it("verify() returns unauthenticated for an unknown key", async () => {
		const s = new ApiKeyStrategy({ findByKey: async () => null });
		expect(await s.verify("nope")).toEqual({
			authenticated: false,
			error: "Invalid API key",
		});
	});

	it("verify() authenticates a known key", async () => {
		const s = new ApiKeyStrategy({ findByKey: async () => ({ user }) });
		const out = await s.verify("good");
		expect(out.authenticated).toBe(true);
		expect(out.user?.id).toBe("u1");
	});

	it("merges scopes into permissions without duplicating or mutating the source", async () => {
		const s = new ApiKeyStrategy({
			findByKey: async () => ({ user, scopes: ["read", "write"] }),
		});
		const out = await s.verify("good");
		expect(out.user?.permissions).toEqual(["read", "write"]);
		// Source object's permissions array must be untouched.
		expect(user.permissions).toEqual(["read"]);
	});
});
