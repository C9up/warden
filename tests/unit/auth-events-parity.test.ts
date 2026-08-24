/**
 * Auth events, named after what `@adonisjs/auth`'s session guard emits
 * (modules/session_guard/main.js):
 *
 *   session_auth:authentication_attempted
 *   session_auth:authentication_succeeded
 *   session_auth:authentication_failed
 *   session_auth:login_attempted
 *   session_auth:login_succeeded
 *   session_auth:logged_out
 *
 * An app auditing logins subscribes to exactly these names, so a migrated
 * listener has to keep firing.
 */
import { describe, expect, it, vi } from "vitest";
import { AuthManager } from "../../src/AuthManager.js";
import { SessionStrategy } from "../../src/strategies/SessionStrategy.js";

function setup() {
	const events: Array<{ event: string; data: unknown }> = [];
	const emitter = {
		emit(event: string, data: unknown) {
			events.push({ event, data });
		},
	};
	const users = new Map([["1", { id: "1", email: "a@b.c" }]]);
	const auth = new AuthManager({
		default: "web",
		guards: {
			web: new SessionStrategy({
				findUser: async (id: string | number) => users.get(String(id)) ?? null,
			}),
		},
	}).setEmitter(emitter);
	return { auth, events };
}

function fakeSession() {
	const store = new Map<string, unknown>();
	return {
		get: (k: string) => store.get(k),
		put: (k: string, v: unknown) => store.set(k, v),
		forget: (k: string) => store.delete(k),
		regenerate: () => {},
	};
}

describe("warden > auth events (AdonisJS parity)", () => {
	it("emits login_attempted then login_succeeded", async () => {
		const { auth, events } = setup();

		await auth.login({ id: "1", email: "a@b.c" }, fakeSession() as never);

		expect(events.map((e) => e.event)).toEqual([
			"session_auth:login_attempted",
			"session_auth:login_succeeded",
		]);
	});

	it("emits logged_out on logout", async () => {
		const { auth, events } = setup();
		await auth.logout(fakeSession() as never);

		expect(events.at(-1)?.event).toBe("session_auth:logged_out");
	});

	it("carries the guard name on the payload", async () => {
		const { auth, events } = setup();
		await auth.login({ id: "1", email: "a@b.c" }, fakeSession() as never);

		expect(events[0]?.data).toMatchObject({ guardName: "web" });
	});

	it("a throwing listener does not break the login", async () => {
		const auth = new AuthManager({
			default: "web",
			guards: {
				web: new SessionStrategy({ findUser: async () => null }),
			},
		}).setEmitter({
			emit() {
				throw new Error("listener exploded");
			},
		});

		// Authentication is not an event bus's business to veto.
		await expect(
			auth.login({ id: "1" }, fakeSession() as never),
		).resolves.toBeUndefined();
	});

	it("works with no emitter wired at all", async () => {
		// warden is a leaf: a host that never calls setEmitter still logs in.
		const auth = new AuthManager({
			default: "web",
			guards: { web: new SessionStrategy({ findUser: async () => null }) },
		});

		await expect(
			auth.login({ id: "1" }, fakeSession() as never),
		).resolves.toBeUndefined();
	});
});
