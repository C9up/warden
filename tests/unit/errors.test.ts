import { Exception } from "@c9up/flare";
import { describe, expect, it } from "vitest";
import { errors } from "../../src/index.js";

describe("warden > errors", () => {
	it("are exported as one namespace of flare exceptions", () => {
		const error = new errors.E_WARDEN_STRATEGY_NOT_FOUND(["api"]);
		expect(error).toBeInstanceOf(Exception);
		expect(error).toMatchObject({
			code: "E_WARDEN_STRATEGY_NOT_FOUND",
			status: 500,
			message: "Auth strategy 'api' not registered",
			help: "Call registerStrategy() before using this strategy name.",
		});
	});

	it("keeps the upstream identifiers and statuses", () => {
		expect(
			new errors.E_UNAUTHORIZED_ACCESS("Unauthorized access", {
				guardDriverName: "jwt",
			}),
		).toMatchObject({
			code: "E_UNAUTHORIZED_ACCESS",
			status: 401,
			guardDriverName: "jwt",
		});
		expect(new errors.E_INVALID_CREDENTIALS()).toMatchObject({
			code: "E_INVALID_CREDENTIALS",
			status: 400,
			message: "Invalid user credentials",
		});
	});
});
