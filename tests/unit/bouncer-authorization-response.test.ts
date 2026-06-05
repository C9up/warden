import { describe, expect, it } from "vitest";
import { AuthorizationResponse } from "../../src/bouncer/AuthorizationResponse.js";

describe("warden > bouncer > AuthorizationResponse", () => {
	it("deny() defaults to status 403 with no message (D6)", () => {
		const response = AuthorizationResponse.deny();
		expect(response.authorized).toBe(false);
		expect(response.status).toBe(403);
		expect(response.message).toBeUndefined();
	});

	it("deny(message, status) carries a custom message + status", () => {
		const response = AuthorizationResponse.deny("nope", 404);
		expect(response.authorized).toBe(false);
		expect(response.status).toBe(404);
		expect(response.message).toBe("nope");
	});

	it("allow() is authorized with no status", () => {
		const response = AuthorizationResponse.allow();
		expect(response.authorized).toBe(true);
		expect(response.status).toBeUndefined();
		expect(response.message).toBeUndefined();
	});

	it("the translation parity field is inert in 56.2 (D6)", () => {
		expect(AuthorizationResponse.allow().translation).toBeUndefined();
		expect(AuthorizationResponse.deny().translation).toBeUndefined();
	});
});
