/**
 * `authFinder` on a real sigil `Hash`, past the hasher's password limits.
 *
 * sigil refuses a password over 1024 bytes (72 for bcrypt): `make` throws and
 * `verify` answers `false` without hashing. A sign-in that hashed with `make`
 * for an unknown account and with `verify` for a known one therefore answered
 * the two differently — a 500 against a 400 — and one request per email listed
 * the registered accounts. Every branch must answer the same
 * `E_INVALID_CREDENTIALS`, at the same cost.
 */
import {
	Container,
	createHttpKernel,
	MiddlewareRegistry,
	Router,
} from "@c9up/ream";
import { Hash } from "@c9up/sigil";
import { beforeAll, describe, expect, it } from "vitest";
import { AuthManager } from "../../src/AuthManager.js";
import { type AuthFinder, authFinder } from "../../src/authFinder.js";
import { E_INVALID_CREDENTIALS } from "../../src/errors.js";
import { JwtStrategy } from "../../src/strategies/JwtStrategy.js";

type Row = { id: string; email: string; passwordHash: string | null };

const KNOWN = "alice@example.com";
const HASHLESS = "sso@example.com";
const UNKNOWN = "nobody@example.com";
const BRANCHES = [KNOWN, HASHLESS, UNKNOWN] as const;

function field(body: unknown, name: string): string {
	const value: unknown =
		typeof body === "object" && body !== null
			? Reflect.get(body, name)
			: undefined;
	return typeof value === "string" ? value : "";
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
	try {
		await promise;
	} catch (error) {
		return error;
	}
	throw new Error("expected the credential check to fail");
}

const hashers = [
	{ name: "argon2", config: { driver: "argon2" }, limit: 1024 },
	{ name: "bcrypt", config: { driver: "bcrypt", rounds: 10 }, limit: 72 },
] as const;

for (const { name, config, limit } of hashers) {
	describe(`warden > authFinder on sigil ${name}, past its ${limit}-byte limit`, () => {
		const tooLong = "a".repeat(limit + 1);
		const atTheLimit = "b".repeat(limit);
		const hash = new Hash({ default: name, list: { [name]: { ...config } } });
		/** Every call the sign-in makes on the hasher: the work a caller times. */
		const calls: string[] = [];
		const rows: Row[] = [];
		let users: AuthFinder<Row>;

		beforeAll(async () => {
			rows.push(
				{
					id: "1",
					email: KNOWN,
					passwordHash: await hash.make("correct horse"),
				},
				{ id: "2", email: HASHLESS, passwordHash: null },
				{
					id: "3",
					email: "long@example.com",
					passwordHash: await hash.make(atTheLimit),
				},
			);
			users = authFinder({
				hash: {
					make: (value) => {
						calls.push("make");
						return hash.make(value);
					},
					verify: (hashed, plain) => {
						calls.push("verify");
						return hash.verify(hashed, plain);
					},
				},
				findForAuth: async (email) =>
					rows.find((row) => row.email === email) ?? null,
				passwordColumnName: "passwordHash",
			});
			// The decoy hash is made by the first sign-in that needs one.
			await failure(users.verifyCredentials(UNKNOWN, "warm-up"));
		});

		it("the hasher itself refuses the password in make and not in verify", async () => {
			// What makes the two calls unequal: the reason the sign-in cannot
			// hash with `make` on one branch and `verify` on the other.
			await expect(hash.make(tooLong)).rejects.toThrow();
			const stored = rows[0]?.passwordHash ?? "";
			expect(await hash.verify(stored, tooLong)).toBe(false);
		});

		it("answers the same E_INVALID_CREDENTIALS on the three branches", async () => {
			for (const password of [tooLong, "wrong"]) {
				for (const uid of BRANCHES) {
					const error = await failure(users.verifyCredentials(uid, password));
					expect(error).toBeInstanceOf(E_INVALID_CREDENTIALS);
					if (!(error instanceof E_INVALID_CREDENTIALS)) continue;
					expect(error.status).toBe(400);
					expect(error.message).toBe("Invalid user credentials");
				}
			}
		});

		it("makes the same hasher calls on the three branches", async () => {
			for (const password of [tooLong, "wrong"]) {
				const seen: string[][] = [];
				for (const uid of BRANCHES) {
					calls.length = 0;
					await failure(users.verifyCredentials(uid, password));
					seen.push([...calls]);
				}
				expect(seen[0]?.length).toBeGreaterThan(0);
				expect(seen[1]).toEqual(seen[0]);
				expect(seen[2]).toEqual(seen[0]);
			}
		});

		it("verifyPassword answers false, without throwing, for a refused password", async () => {
			for (const row of rows.slice(0, 2)) {
				expect(await users.verifyPassword(row, tooLong)).toBe(false);
			}
		});

		it("still signs in, up to the last byte the hasher accepts", async () => {
			expect((await users.verifyCredentials(KNOWN, "correct horse")).id).toBe(
				"1",
			);
			expect(
				(await users.verifyCredentials("long@example.com", atTheLimit)).id,
			).toBe("3");
		});

		it("over HTTP, one request per email no longer tells the accounts apart", async () => {
			const router = new Router();
			router.post("/login", async (ctx) => {
				const body: unknown = JSON.parse(ctx.request.raw());
				const user = await users.verifyCredentials(
					field(body, "email"),
					field(body, "password"),
				);
				ctx.response.json({ id: user.id });
			});
			const kernel = createHttpKernel({
				router,
				container: new Container(),
				middleware: new MiddlewareRegistry(),
			});
			const login = async (email: string, password: string) => {
				const response = await kernel({
					method: "POST",
					path: "/login",
					query: "",
					headers: {
						accept: "application/json",
						"content-type": "application/json",
					},
					body: JSON.stringify({ email, password }),
				});
				return { status: response.status, body: String(response.body) };
			};

			const answers = [];
			for (const uid of BRANCHES) answers.push(await login(uid, tooLong));
			expect(answers[0]).toEqual({
				status: 400,
				body: '{"errors":[{"message":"Invalid user credentials"}]}',
			});
			expect(answers[1]).toEqual(answers[0]);
			expect(answers[2]).toEqual(answers[0]);
			expect((await login(KNOWN, "correct horse")).status).toBe(200);
		});

		it("through a guard, the three are a plain rejection, never a strategy crash", async () => {
			const manager = new AuthManager({
				default: "jwt",
				guards: {
					jwt: new JwtStrategy({
						secret: "s".repeat(32),
						findUser: async (id) => ({ id }),
						verifyCredentials: users.verifyCredentials,
					}),
				},
			});
			for (const email of BRANCHES) {
				expect(
					await manager.authenticate({ email, password: tooLong }),
				).toEqual({ authenticated: false, error: "Invalid credentials" });
			}
		});
	});
}
