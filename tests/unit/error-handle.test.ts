/**
 * warden's upstream errors render themselves (`handle`), so one raised
 * outside warden's middleware answers the same way. `E_UNAUTHORIZED_ACCESS`
 * writes exactly what the middleware writes; `E_INVALID_CREDENTIALS` and
 * `E_AUTHORIZATION_FAILURE` negotiate as upstream.
 */
import { describe, expect, it, vi } from "vitest";
import { AuthorizationResponse } from "../../src/bouncer/AuthorizationResponse.js";
import { errors } from "../../src/index.js";
import { renderAuthError, type WardenContext } from "../../src/middleware.js";

function unauthorizedContext(accept: string) {
	const captured: {
		status?: number;
		body?: unknown;
		redirectedTo?: string;
		headers: Record<string, string>;
	} = { headers: {} };
	const ctx: WardenContext = {
		request: { headers: () => ({ accept }) },
		response: {
			status: (code) => {
				captured.status = code;
			},
			json: (data) => {
				captured.body = data;
			},
			header: (name, value) => {
				captured.headers[name] = value;
			},
			redirect: (url) => {
				captured.redirectedTo = url;
			},
		},
	};
	return { ctx, captured };
}

function negotiatedContext(
	format: string | null,
	extra: { method?: string; session?: object } = {},
) {
	const status = vi.fn();
	const send = vi.fn();
	const redirect = vi.fn();
	const ctx = {
		request: {
			accepts: <T extends string>(types: T[]): T | null =>
				types.find((type) => type === format) ?? null,
			method: () => extra.method ?? "GET",
		},
		response: { status, send, redirect },
		...(extra.session ? { session: extra.session } : {}),
	};
	return { ctx, status, send, redirect };
}

function flashingSession() {
	return { flashExcept: vi.fn(), flash: vi.fn(), flashErrors: vi.fn() };
}

describe("warden > E_UNAUTHORIZED_ACCESS.handle", () => {
	it("carries upstream's identifier", () => {
		const error = new errors.E_UNAUTHORIZED_ACCESS("Unauthorized access", {
			guardDriverName: "session",
		});
		expect(error.identifier).toBe("errors.E_UNAUTHORIZED_ACCESS");
	});

	it("writes what the middleware writes: challenge and 401 JSON", async () => {
		const error = new errors.E_UNAUTHORIZED_ACCESS("Unauthorized access", {
			guardDriverName: "basic_auth",
			challenge: 'Basic realm="Admin", charset="UTF-8"',
		});
		const viaHandle = unauthorizedContext("application/json");
		const viaMiddleware = unauthorizedContext("application/json");
		await error.handle(error, viaHandle.ctx);
		renderAuthError(viaMiddleware.ctx, error);
		expect(viaHandle.captured).toEqual(viaMiddleware.captured);
		expect(viaHandle.captured).toEqual({
			status: 401,
			body: {
				error: {
					code: "E_UNAUTHORIZED_ACCESS",
					message: "Unauthorized access",
				},
			},
			headers: { "WWW-Authenticate": 'Basic realm="Admin", charset="UTF-8"' },
		});
	});

	it("redirects a browser to the session guard's login route", async () => {
		const error = new errors.E_UNAUTHORIZED_ACCESS("Unauthorized access", {
			guardDriverName: "session",
			redirectTo: "/login",
		});
		const { ctx, captured } = unauthorizedContext("text/html");
		await error.handle(error, ctx);
		expect(captured.redirectedTo).toBe("/login");
		expect(captured.status).toBeUndefined();
	});

	it("translates the message through ctx.i18n", async () => {
		const error = new errors.E_UNAUTHORIZED_ACCESS("Unauthorized access", {
			guardDriverName: "jwt",
		});
		const { ctx, captured } = unauthorizedContext("application/json");
		const t = vi.fn(() => "Accès non autorisé");
		await error.handle(error, Object.assign(ctx, { i18n: { t } }));
		expect(t).toHaveBeenCalledWith(
			"errors.E_UNAUTHORIZED_ACCESS",
			{},
			{ defaultValue: "Unauthorized access" },
		);
		expect(captured.body).toEqual({
			error: { code: "E_UNAUTHORIZED_ACCESS", message: "Accès non autorisé" },
		});
	});
});

describe("warden > E_INVALID_CREDENTIALS.handle", () => {
	it("carries upstream's identifier", () => {
		expect(new errors.E_INVALID_CREDENTIALS().identifier).toBe(
			"errors.E_INVALID_CREDENTIALS",
		);
	});

	it("answers JSON with { errors: [{ message }] }", async () => {
		const error = new errors.E_INVALID_CREDENTIALS();
		const { ctx, status, send } = negotiatedContext("json");
		await error.handle(error, ctx);
		expect(status).toHaveBeenCalledWith(400);
		expect(send).toHaveBeenCalledWith({
			errors: [{ message: "Invalid user credentials" }],
		});
	});

	it("flashes the form back and redirects a browser with a session", async () => {
		const error = new errors.E_INVALID_CREDENTIALS();
		const session = flashingSession();
		const { ctx, send, redirect } = negotiatedContext("html", { session });
		await error.handle(error, ctx);
		expect(session.flashExcept).toHaveBeenCalledWith([
			"_csrf",
			"_method",
			"password",
			"password_confirmation",
		]);
		expect(session.flash).toHaveBeenCalledWith(
			"error",
			"Invalid user credentials",
		);
		expect(session.flashErrors).toHaveBeenCalledWith({
			E_INVALID_CREDENTIALS: "Invalid user credentials",
		});
		expect(redirect).toHaveBeenCalledWith("back", true);
		expect(send).not.toHaveBeenCalled();
	});

	it("answers the message as text without a session", async () => {
		const error = new errors.E_INVALID_CREDENTIALS();
		const { ctx, status, send } = negotiatedContext(null);
		await error.handle(error, ctx);
		expect(status).toHaveBeenCalledWith(400);
		expect(send).toHaveBeenCalledWith("Invalid user credentials");
	});
});

describe("warden > E_AUTHORIZATION_FAILURE.handle", () => {
	it("answers a JSON:API client with the denial's status", async () => {
		const error = new errors.E_AUTHORIZATION_FAILURE(
			AuthorizationResponse.deny("Not found", 404),
		);
		const { ctx, status, send } = negotiatedContext("application/vnd.api+json");
		await error.handle(error, ctx);
		expect(status).toHaveBeenCalledWith(404);
		expect(send).toHaveBeenCalledWith({
			errors: [{ code: "E_AUTHORIZATION_FAILURE", title: "Not found" }],
		});
	});

	it("redirects a form submission back, with the message flashed", async () => {
		const error = new errors.E_AUTHORIZATION_FAILURE(
			AuthorizationResponse.deny(),
		);
		const session = flashingSession();
		const { ctx, redirect } = negotiatedContext("html", {
			method: "POST",
			session,
		});
		await error.handle(error, ctx);
		expect(session.flash).toHaveBeenCalledWith("error", "Access denied");
		expect(session.flashErrors).toHaveBeenCalledWith({
			E_AUTHORIZATION_FAILURE: "Access denied",
		});
		expect(redirect).toHaveBeenCalledWith("back", true);
	});

	it("answers a page request with the message as text, session or not", async () => {
		const error = new errors.E_AUTHORIZATION_FAILURE(
			AuthorizationResponse.deny(),
		);
		const session = flashingSession();
		const { ctx, status, send, redirect } = negotiatedContext("html", {
			session,
		});
		await error.handle(error, ctx);
		expect(redirect).not.toHaveBeenCalled();
		expect(session.flash).not.toHaveBeenCalled();
		expect(status).toHaveBeenCalledWith(403);
		expect(send).toHaveBeenCalledWith("Access denied");
	});
});
