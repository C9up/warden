/**
 * `@Role('a', 'b')` and `@Guard('jwt', 'api')` mean the same on every path:
 * warden's middleware and ream's route gate (which reads the same decorators
 * when the route's handler is a controller action) let the same requests
 * through. Both require every role `@Role` names, and accept a request
 * authenticated by any one guard `@Guard` names.
 */
import "reflect-metadata";
import {
	Container,
	createHttpKernel,
	type HttpContext,
	MiddlewareRegistry,
	Router,
} from "@c9up/ream";
import { describe, expect, it } from "vitest";
import { AuthManager, type AuthStrategy } from "../../src/AuthManager.js";
import { Guard, Role } from "../../src/Guard.js";
import {
	wardenMiddleware as unhandledWardenMiddleware,
	type WardenContext,
} from "../../src/middleware.js";
import { withExceptionHandler } from "./support/exceptionHandler.js";

const wardenMiddleware = withExceptionHandler(unhandledWardenMiddleware);

class ReportsController {
	@Role("a", "b")
	async export(ctx: HttpContext) {
		ctx.response.send("ran");
	}
}

/** The token is the user's roles, comma-separated. */
const jwt: AuthStrategy = {
	name: "jwt",
	async authenticate() {
		return { authenticated: false };
	},
	async verify(token) {
		const roles = token === "none" ? [] : token.split(",");
		return { authenticated: true, user: { id: "u1", roles } };
	},
};

/** Whether warden's middleware lets a user holding `roles` reach the action. */
async function wardenLets(roles: string[]): Promise<boolean> {
	const auth = new AuthManager({ default: "jwt", guards: { jwt } });
	const token = roles.length === 0 ? "none" : roles.join(",");
	let reached = false;
	const ctx: WardenContext = {
		request: { headers: () => ({ authorization: `Bearer ${token}` }) },
		response: {
			status() {},
			json() {},
		},
		route: { controller: ReportsController.prototype, action: "export" },
		containerResolver: {
			async make(t) {
				if (t === AuthManager) return auth;
				throw new Error(`No binding for ${String(t)}`);
			},
		},
	};
	await wardenMiddleware(ctx, () => {
		reached = true;
	});
	return reached;
}

/** Whether ream's route gate alone lets a user holding `roles` reach the action. */
async function reamLets(roles: string[]): Promise<boolean> {
	const router = new Router();
	router.get("/reports", [ReportsController, "export"]);
	const kernel = createHttpKernel({
		router,
		container: new Container(),
		middleware: new MiddlewareRegistry(),
		serverMiddleware: [
			async (ctx: HttpContext, next: () => Promise<void>) => {
				ctx.auth = {
					isAuthenticated: true,
					authenticatedViaGuard: "jwt",
					user: { id: "u1", roles },
				};
				await next();
			},
		],
	});
	const response = await kernel({
		method: "GET",
		path: "/reports",
		query: "",
		headers: { accept: "application/json" },
		body: "",
	});
	return response.status === 200;
}

describe("@Role('a', 'b') on warden's middleware and on ream's route gate", () => {
	const cases: Array<[string[], boolean]> = [
		[[], false],
		[["a"], false],
		[["b"], false],
		[["a", "b"], true],
		[["a", "b", "c"], true],
	];

	for (const [roles, allowed] of cases) {
		it(`${allowed ? "lets" : "refuses"} a user holding [${roles.join(", ")}], on both`, async () => {
			expect(await wardenLets(roles)).toBe(allowed);
			expect(await reamLets(roles)).toBe(allowed);
		});
	}
});

class AccountController {
	@Guard("jwt", "api")
	async show(ctx: HttpContext) {
		ctx.response.send("ran");
	}
}

/** A bearer guard that accepts the tokens `<name>:<user>`. */
function bearer(name: string): AuthStrategy {
	return {
		name,
		async authenticate() {
			return { authenticated: false };
		},
		async verify(token) {
			return token.startsWith(`${name}:`)
				? { authenticated: true, user: { id: token.slice(name.length + 1) } }
				: { authenticated: false, error: "bad token" };
		},
	};
}

/** Whether warden's middleware lets a request bearing `token` reach the action. */
async function wardenLetsGuard(token: string): Promise<boolean> {
	const auth = new AuthManager({
		default: "jwt",
		guards: { jwt: bearer("jwt"), api: bearer("api"), other: bearer("other") },
	});
	let reached = false;
	const ctx: WardenContext = {
		request: { headers: () => ({ authorization: `Bearer ${token}` }) },
		response: {
			status() {},
			json() {},
		},
		route: { controller: AccountController.prototype, action: "show" },
		containerResolver: {
			async make(t) {
				if (t === AuthManager) return auth;
				throw new Error(`No binding for ${String(t)}`);
			},
		},
	};
	await wardenMiddleware(ctx, () => {
		reached = true;
	});
	return reached;
}

/** Whether ream's route gate alone lets a request authenticated by `guard` through. */
async function reamLetsGuard(guard: string): Promise<boolean> {
	const router = new Router();
	router.get("/account", [AccountController, "show"]);
	const kernel = createHttpKernel({
		router,
		container: new Container(),
		middleware: new MiddlewareRegistry(),
		serverMiddleware: [
			async (ctx: HttpContext, next: () => Promise<void>) => {
				ctx.auth = {
					isAuthenticated: true,
					authenticatedViaGuard: guard,
					user: { id: "u1" },
				};
				await next();
			},
		],
	});
	const response = await kernel({
		method: "GET",
		path: "/account",
		query: "",
		headers: { accept: "application/json" },
		body: "",
	});
	return response.status === 200;
}

describe("@Guard('jwt', 'api') on warden's middleware and on ream's route gate", () => {
	const cases: Array<[string, boolean]> = [
		["jwt", true],
		["api", true],
		["other", false],
	];

	for (const [guard, allowed] of cases) {
		it(`${allowed ? "lets" : "refuses"} a request authenticated by ${guard}, on both`, async () => {
			expect(await wardenLetsGuard(`${guard}:u1`)).toBe(allowed);
			expect(await reamLetsGuard(guard)).toBe(allowed);
		});
	}
});
