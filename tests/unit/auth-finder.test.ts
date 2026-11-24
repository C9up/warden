/**
 * `authFinder` — the timing-safe credential check (the counterpart of the
 * upstream `withAuthFinder` mixin's `verifyCredentials`).
 *
 * The attack: a login endpoint that returns early for an unknown account
 * answers in microseconds, and one that hashes for a known account answers in
 * ~100 ms, so an anonymous caller enumerates registered emails by timing.
 * The proof here is cost, not wall-clock: an unknown uid runs exactly the one
 * verification a known uid runs, and every failure raises the same error.
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

	it("runs for an unknown uid the one verification a known uid runs", async () => {
		const { hash, users } = setup();

		await failure(users.verifyCredentials("known@example.com", "wrong"));
		const known = [...hash.calls];
		hash.calls.length = 0;
		await failure(users.verifyCredentials("nobody@example.com", "wrong"));
		const first = [...hash.calls];
		hash.calls.length = 0;
		await failure(users.verifyCredentials("nobody@example.com", "wrong"));
		const unknown = [...hash.calls];

		expect(known).toEqual(["verify"]);
		// The decoy hash is made once, by the first sign-in that needs it.
		expect(first).toEqual(["make", "verify"]);
		// The early return used to do no hash work at all here.
		expect(unknown).toEqual(["verify"]);
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

	it("an account with no password hash still runs one verification and fails", async () => {
		const { hash, users } = setup();
		await failure(users.verifyCredentials("nobody@example.com", "warm-up"));
		hash.calls.length = 0;
		await failure(users.verifyCredentials("sso@example.com", "anything"));
		expect(hash.calls).toEqual(["verify"]);
	});

	it("never authenticates on the decoy, even with a hasher that says yes", async () => {
		const users = authFinder({
			hash: {
				make: async (value: string) => `hashed:${value}`,
				verify: async () => true,
			},
			findForAuth: async (uid: string): Promise<Row | null> =>
				uid === "sso@example.com"
					? { id: "2", email: uid, password: null }
					: null,
		});
		expect(
			await failure(users.verifyCredentials("nobody@example.com", "x")),
		).toBeInstanceOf(E_INVALID_CREDENTIALS);
		expect(
			await failure(users.verifyCredentials("sso@example.com", "x")),
		).toBeInstanceOf(E_INVALID_CREDENTIALS);
		expect(
			await users.verifyPassword(
				{ id: "2", email: "sso@example.com", password: null },
				"x",
			),
		).toBe(false);
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

describe("warden > authFinder with a hasher that throws", () => {
	const rows: Row[] = [
		{ id: "1", email: "known@example.com", password: "hashed:secret" },
		{ id: "2", email: "sso@example.com", password: null },
	];
	const findForAuth = async (uid: string) =>
		rows.find((row) => row.email === uid) ?? null;
	const uids = ["known@example.com", "sso@example.com", "nobody@example.com"];

	/** A hasher whose `make` AND `verify` throw on a password over 8 chars. */
	function strictHasher() {
		const calls: string[] = [];
		const refuse = (value: string) => {
			if (value.length > 8 && !value.startsWith("hashed:")) {
				throw new Error("password too long for this hasher");
			}
		};
		return {
			calls,
			async make(value: string) {
				calls.push("make");
				// The decoy password is 43 chars: a real hasher accepts it.
				if (value.length !== 43) refuse(value);
				return `hashed:${value}`;
			},
			async verify(hashed: string, plain: string) {
				calls.push("verify");
				if (plain.length !== 43) refuse(plain);
				return hashed === `hashed:${plain}`;
			},
		};
	}

	it("a password the hasher refuses is a wrong password on every branch, at the same cost", async () => {
		const hash = strictHasher();
		const users = authFinder({ hash, findForAuth });
		await failure(users.verifyCredentials("nobody@example.com", "warm-up"));

		const seen: string[][] = [];
		for (const uid of uids) {
			hash.calls.length = 0;
			const error = await failure(
				users.verifyCredentials(uid, "far-too-long-a-password"),
			);
			expect(error).toBeInstanceOf(E_INVALID_CREDENTIALS);
			seen.push([...hash.calls]);
		}
		// The refused verification, then the hasher verifying its own decoy.
		expect(seen).toEqual([
			["verify", "verify"],
			["verify", "verify"],
			["verify", "verify"],
		]);
		const known = rows[0];
		if (known === undefined) throw new Error("fixture row missing");
		expect(await users.verifyPassword(known, "far-too-long-a-password")).toBe(
			false,
		);
		// And the hasher still signs the right password in.
		expect((await users.verifyCredentials(known.email, "secret")).id).toBe("1");
	});

	it("a hasher out of service stays a crash on every branch", async () => {
		const outage = new Error("native binary missing");
		const users = authFinder({
			hash: {
				make: async () => {
					throw outage;
				},
				verify: async () => {
					throw outage;
				},
			},
			findForAuth,
		});
		for (const uid of uids) {
			expect(await failure(users.verifyCredentials(uid, "secret"))).toBe(
				outage,
			);
		}
	});

	it("a hasher that cannot verify its own decoy is out of service too", async () => {
		const broken = new Error("verify is broken");
		const users = authFinder({
			hash: {
				make: async (value: string) => `hashed:${value}`,
				verify: async () => {
					throw broken;
				},
			},
			findForAuth,
		});
		expect(
			await failure(users.verifyCredentials("known@example.com", "secret")),
		).toBe(broken);
	});

	it("asks for the decoy again after the hasher comes back", async () => {
		let down = true;
		const users = authFinder({
			hash: {
				make: async (value: string) => {
					if (down) throw new Error("down");
					return `hashed:${value}`;
				},
				verify: async (hashed: string, plain: string) =>
					hashed === `hashed:${plain}`,
			},
			findForAuth,
		});
		const first = await failure(
			users.verifyCredentials("nobody@example.com", "secret"),
		);
		expect(first).not.toBeInstanceOf(E_INVALID_CREDENTIALS);
		down = false;
		expect(
			await failure(users.verifyCredentials("nobody@example.com", "secret")),
		).toBeInstanceOf(E_INVALID_CREDENTIALS);
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
