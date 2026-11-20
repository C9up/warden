/**
 * `authFinder` — the timing-safe credential check (the counterpart of the
 * upstream `withAuthFinder` mixin's `verifyCredentials`).
 *
 * The attack: a login endpoint that returns early for an unknown account
 * answers in microseconds, and one that hashes for a known account answers in
 * ~100 ms, so an anonymous caller enumerates registered emails by timing.
 * The proof here is cost, not wall-clock: an unknown uid pays exactly the one
 * hash a known uid pays, and every failure raises the same error.
 */
import { describe, expect, it } from "vitest";
import { AuthManager } from "../../src/AuthManager.js";
import { authFinder } from "../../src/authFinder.js";
import { E_INVALID_CREDENTIALS } from "../../src/errors.js";
import * as barrel from "../../src/index.js";
import { BasicAuthStrategy } from "../../src/strategies/BasicAuthStrategy.js";
import { JwtStrategy } from "../../src/strategies/JwtStrategy.js";

type Row = {
	id: string;
	email: string;
	password: string | null;
};

/** A hasher that records every call: the hash work an attacker would time. */
function countingHasher() {
	const calls: string[] = [];
	return {
		calls,
		async make(value: string) {
			calls.push("make");
			return `hashed:${value}`;
		},
		async verify(hashed: string, plain: string) {
			calls.push("verify");
			return hashed === `hashed:${plain}`;
		},
	};
}

function setup() {
	const hash = countingHasher();
	const rows: Row[] = [
		{ id: "1", email: "known@example.com", password: "hashed:secret" },
		{ id: "2", email: "sso@example.com", password: null },
	];
	const users = authFinder({
		hash,
		findForAuth: async (uid: string) =>
			rows.find((row) => row.email === uid) ?? null,
	});
	return { hash, users };
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
	try {
		await promise;
	} catch (error) {
		return error;
	}
	throw new Error("expected the credential check to fail");
}

describe("warden > authFinder.verifyCredentials", () => {
	it("returns the user for the right password", async () => {
		const { users } = setup();
		const user = await users.verifyCredentials("known@example.com", "secret");
		expect(user.id).toBe("1");
	});

	it("pays one hash for an unknown uid, as a known uid does", async () => {
		const { hash, users } = setup();

		await failure(users.verifyCredentials("known@example.com", "wrong"));
		const known = [...hash.calls];
		hash.calls.length = 0;
		await failure(users.verifyCredentials("nobody@example.com", "wrong"));
		const unknown = [...hash.calls];

		expect(known).toEqual(["verify"]);
		// The early return used to do no hash work at all here.
		expect(unknown).toHaveLength(1);
	});

	it("raises E_INVALID_CREDENTIALS for every failure, indistinguishably", async () => {
		const { users } = setup();
		const errors = await Promise.all([
			failure(users.verifyCredentials("known@example.com", "wrong")),
			failure(users.verifyCredentials("nobody@example.com", "wrong")),
			failure(users.verifyCredentials("", "secret")),
			failure(users.verifyCredentials("known@example.com", "")),
			failure(users.verifyCredentials("sso@example.com", "anything")),
		]);
		for (const error of errors) {
			expect(error).toBeInstanceOf(E_INVALID_CREDENTIALS);
			if (!(error instanceof E_INVALID_CREDENTIALS)) continue;
			expect(error.code).toBe("E_INVALID_CREDENTIALS");
			expect(error.message).toBe("Invalid user credentials");
		}
	});

	it("an account with no password hash still pays one hash and fails", async () => {
		const { hash, users } = setup();
		await failure(users.verifyCredentials("sso@example.com", "anything"));
		expect(hash.calls).toHaveLength(1);
	});

	it("verifyPassword checks a known user's password", async () => {
		const { users } = setup();
		const row: Row = { id: "1", email: "k", password: "hashed:secret" };
		expect(await users.verifyPassword(row, "secret")).toBe(true);
		expect(await users.verifyPassword(row, "nope")).toBe(false);
		expect(await users.verifyPassword({ ...row, password: null }, "x")).toBe(
			false,
		);
	});

	it("reads a custom password column", async () => {
		const hash = countingHasher();
		const users = authFinder({
			hash,
			passwordColumnName: "passwordHash",
			findForAuth: async () => ({ id: "1", passwordHash: "hashed:pw" }),
		});
		expect((await users.verifyCredentials("a", "pw")).id).toBe("1");
	});

	it("is exported from the barrel", () => {
		expect(barrel.authFinder).toBe(authFinder);
	});
});

describe("warden > a strategy wired to authFinder", () => {
	const secret = "s".repeat(32);

	it("a Basic guard answers a plain rejection, not a crash", async () => {
		const { users } = setup();
		const manager = new AuthManager({
			default: "basic",
			guards: {
				basic: new BasicAuthStrategy({
					verifyCredentials: users.verifyCredentials,
				}),
			},
		});
		const header = (uid: string, pw: string) =>
			`Basic ${Buffer.from(`${uid}:${pw}`).toString("base64")}`;

		const wrong = await manager.verify(header("nobody@example.com", "x"));
		expect(wrong).toEqual({
			authenticated: false,
			error: "Invalid credentials",
		});
		const right = await manager.verify(header("known@example.com", "secret"));
		expect(right.authenticated).toBe(true);
	});

	it("a JWT login answers a plain rejection, not a thrown error", async () => {
		const { users } = setup();
		const manager = new AuthManager({
			default: "jwt",
			guards: {
				jwt: new JwtStrategy({
					secret,
					findUser: async (id) => ({ id }),
					verifyCredentials: users.verifyCredentials,
				}),
			},
		});

		const wrong = await manager.authenticate({
			email: "nobody@example.com",
			password: "x",
		});
		expect(wrong).toEqual({
			authenticated: false,
			error: "Invalid credentials",
		});
	});

	it("an outage in the user lookup is still a crash, not a wrong password", async () => {
		const manager = new AuthManager({
			default: "jwt",
			guards: {
				jwt: new JwtStrategy({
					secret,
					findUser: async (id) => ({ id }),
					verifyCredentials: authFinder({
						hash: countingHasher(),
						findForAuth: async (): Promise<Row | null> => {
							throw new Error("database down");
						},
					}).verifyCredentials,
				}),
			},
		});
		const errorLog = console.error;
		console.error = () => {};
		try {
			const result = await manager.authenticate({
				email: "known@example.com",
				password: "x",
			});
			expect(result).toEqual({ authenticated: false, strategyCrash: true });
		} finally {
			console.error = errorLog;
		}
	});
});
