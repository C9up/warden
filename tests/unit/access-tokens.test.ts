/**
 * Access tokens and their provider: the token format, hashed storage,
 * constant-time verification, expiry, abilities, last use, owner-scoped
 * management and revocation.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	AccessToken,
	AccessTokensProvider,
	crc32,
	MemoryAccessTokenStore,
} from "../../src/AccessToken.js";
import { E_UNAUTHORIZED_ACCESS } from "../../src/errors.js";
import { Secret } from "../../src/Secret.js";

function defined<T>(value: T | null | undefined): T {
	if (value == null) throw new Error("expected a defined value");
	return value;
}

function provider(
	options: { expiresIn?: number | string; type?: string } = {},
) {
	const store = new MemoryAccessTokenStore();
	return { store, tokens: new AccessTokensProvider({ store, ...options }) };
}

const alice = { id: "alice" };
const bob = { id: "bob" };

afterEach(() => {
	vi.useRealTimers();
});

describe("warden > access token format", () => {
	it("computes the standard CRC-32", () => {
		expect(crc32("123456789")).toBe(0xcbf43926);
		expect(crc32("")).toBe(0);
	});

	it("is prefixed, splits into identifier and secret, and checksums the secret", async () => {
		const { tokens } = provider();
		const token = await tokens.create(alice);
		const value = defined(token.value).release();

		expect(value.startsWith("oat_")).toBe(true);
		const decoded = defined(AccessToken.decode("oat_", value));
		expect(decoded.identifier).toBe(token.identifier);
		// secret = 40 random characters + their CRC-32 in decimal, which is
		// what lets a scanner recognise a leaked token.
		const secret = decoded.secret.release();
		const seed = secret.slice(0, 40);
		expect(secret.slice(40)).toBe(String(crc32(seed)));
	});

	it("stores only the hash of the secret", async () => {
		const { store, tokens } = provider();
		const token = await tokens.create(alice);
		const secret = defined(
			AccessToken.decode("oat_", defined(token.value).release()),
		).secret.release();

		const row = defined(await store.find(token.identifier));
		expect(JSON.stringify(row)).not.toContain(secret);
		expect(row.hash).toMatch(/^[0-9a-f]{64}$/);
	});

	it("never serialises the value except on the token just minted", async () => {
		const { tokens } = provider();
		const minted = await tokens.create(alice, ["a"], { name: "CI" });
		const value = defined(minted.value).release();
		expect(minted.toJSON()).toMatchObject({
			type: "bearer",
			name: "CI",
			token: value,
			abilities: ["a"],
		});

		const verified = defined(await tokens.verify(new Secret(value)));
		expect(verified.toJSON().token).toBeUndefined();
		expect(JSON.stringify(verified)).not.toContain(value.slice(4));
	});

	it("decodes nothing that is not one of ours", () => {
		for (const value of [undefined, 42, "", "oat_", "abc.def", "oat_abc"]) {
			expect(AccessToken.decode("oat_", value)).toBeNull();
		}
	});
});

describe("warden > access token abilities", () => {
	const token = (abilities?: string[]) =>
		new AccessToken({
			identifier: "1",
			tokenableId: "alice",
			type: "auth_token",
			name: null,
			hash: "h",
			abilities,
			createdAt: new Date(),
			updatedAt: new Date(),
			lastUsedAt: null,
			expiresAt: null,
		});

	it("grants everything when none are given", () => {
		expect(token().abilities).toEqual(["*"]);
		expect(token().allows("anything")).toBe(true);
	});

	it("grants exactly what is listed, and nothing for an empty list", () => {
		expect(token(["read"]).allows("read")).toBe(true);
		expect(token(["read"]).denies("write")).toBe(true);
		expect(token([]).allows("read")).toBe(false);
	});

	it("authorize() throws E_UNAUTHORIZED_ACCESS for a missing ability", () => {
		expect(() => token(["read"]).authorize("read")).not.toThrow();
		expect(() => token(["read"]).authorize("write")).toThrow(
			E_UNAUTHORIZED_ACCESS,
		);
	});
});

describe("warden > AccessTokensProvider.verify", () => {
	it("verifies a minted value and records the use", async () => {
		const { store, tokens } = provider();
		const minted = await tokens.create(alice, ["read"]);

		const verified = defined(
			await tokens.verify(new Secret(defined(minted.value).release())),
		);

		expect(verified.tokenableId).toBe("alice");
		expect(verified.abilities).toEqual(["read"]);
		expect(verified.lastUsedAt).toBeInstanceOf(Date);
		expect(
			defined(await store.find(minted.identifier)).lastUsedAt,
		).not.toBeNull();
	});

	it("refuses a wrong secret without recording a use", async () => {
		const { store, tokens } = provider();
		const minted = await tokens.create(alice);
		const forged = `oat_${Buffer.from(minted.identifier).toString("base64url")}.${Buffer.from("guess").toString("base64url")}`;

		expect(await tokens.verify(new Secret(forged))).toBeNull();
		// Knowing an identifier must not let anyone move "last used".
		expect(defined(await store.find(minted.identifier)).lastUsedAt).toBeNull();
	});

	it("refuses an expired token", async () => {
		vi.useFakeTimers();
		const { tokens } = provider({ expiresIn: "1 hour" });
		const value = defined((await tokens.create(alice)).value);

		expect(await tokens.verify(value)).not.toBeNull();
		vi.advanceTimersByTime(3_600_001);
		expect(await tokens.verify(value)).toBeNull();
	});

	it("lets a call override the provider's lifetime", async () => {
		const { tokens } = provider({ expiresIn: 60 });
		const before = Date.now();
		const token = await tokens.create(alice, ["*"], { expiresIn: "30 days" });

		const expiresAt = defined(token.expiresAt).getTime();
		expect(expiresAt).toBeGreaterThanOrEqual(before + 30 * 86_400_000);
		expect(expiresAt).toBeLessThan(before + 30 * 86_400_000 + 5_000);
	});

	it("does not expire a token minted without a lifetime", async () => {
		const { tokens } = provider();
		const token = await tokens.create(alice);
		expect(token.expiresAt).toBeNull();
		expect(token.isExpired()).toBe(false);
	});

	it("refuses a token of another type", async () => {
		const store = new MemoryAccessTokenStore();
		const apiTokens = new AccessTokensProvider({ store, type: "api" });
		const deviceTokens = new AccessTokensProvider({ store, type: "device" });
		const value = defined((await apiTokens.create(alice)).value);

		expect(await deviceTokens.verify(value)).toBeNull();
		expect(await apiTokens.verify(value)).not.toBeNull();
	});

	it("refuses a token minted under another prefix", async () => {
		const store = new MemoryAccessTokenStore();
		const value = defined(
			(await new AccessTokensProvider({ store, prefix: "pat_" }).create(alice))
				.value,
		);
		expect(await new AccessTokensProvider({ store }).verify(value)).toBeNull();
	});
});

describe("warden > AccessTokensProvider — management", () => {
	it("finds, lists and deletes a user's tokens only", async () => {
		const { tokens } = provider();
		const mine = await tokens.create(alice);
		await tokens.create(bob);

		expect(await tokens.find(alice, mine.identifier)).not.toBeNull();
		expect(await tokens.find(bob, mine.identifier)).toBeNull();
		expect(await tokens.delete(bob, mine.identifier)).toBe(0);
		expect(await tokens.all(alice)).toHaveLength(1);

		expect(await tokens.delete(alice, mine.identifier)).toBe(1);
		expect(await tokens.all(alice)).toHaveLength(0);
		expect(await tokens.all(bob)).toHaveLength(1);
	});

	it("deleteAll removes every token of the user and type", async () => {
		const store = new MemoryAccessTokenStore();
		const tokens = new AccessTokensProvider({ store });
		const other = new AccessTokensProvider({ store, type: "device" });
		await tokens.create(alice);
		await tokens.create(alice);
		await other.create(alice);
		await tokens.create(bob);

		expect(await tokens.deleteAll(alice)).toBe(2);
		expect(await other.all(alice)).toHaveLength(1);
		expect(await tokens.all(bob)).toHaveLength(1);
	});

	it("lists the most recently used first, never-used last", async () => {
		vi.useFakeTimers();
		const { tokens } = provider();
		const unused = await tokens.create(alice, ["*"], { name: "unused" });
		vi.advanceTimersByTime(10);
		const older = await tokens.create(alice, ["*"], { name: "older" });
		const newer = await tokens.create(alice, ["*"], { name: "newer" });
		await tokens.verify(defined(older.value));
		vi.advanceTimersByTime(10);
		await tokens.verify(defined(newer.value));

		expect((await tokens.all(alice)).map((t) => t.name)).toEqual([
			"newer",
			"older",
			"unused",
		]);
		expect(unused.lastUsedAt).toBeNull();
	});
});

describe("warden > AccessTokensProvider.invalidate", () => {
	it("revokes the token behind a presented value", async () => {
		const { tokens } = provider();
		const value = defined((await tokens.create(alice)).value);

		expect(await tokens.invalidate(value)).toBe(true);
		expect(await tokens.verify(value)).toBeNull();
		expect(await tokens.invalidate(value)).toBe(false);
	});

	it("does not revoke from an identifier alone", async () => {
		const { store, tokens } = provider();
		const minted = await tokens.create(alice);
		const forged = `oat_${Buffer.from(minted.identifier).toString("base64url")}.${Buffer.from("guess").toString("base64url")}`;

		expect(await tokens.invalidate(new Secret(forged))).toBe(false);
		expect(await store.find(minted.identifier)).not.toBeNull();
	});
});

describe("warden > AccessTokensProvider configuration", () => {
	const store = new MemoryAccessTokenStore();

	it("refuses a secret short enough to guess", () => {
		expect(
			() => new AccessTokensProvider({ store, tokenSecretLength: 8 }),
		).toThrow(/tokenSecretLength/);
	});

	it("refuses a prefix the value could not be split after", () => {
		expect(() => new AccessTokensProvider({ store, prefix: "" })).toThrow(
			/prefix/,
		);
		expect(() => new AccessTokensProvider({ store, prefix: "a.b" })).toThrow(
			/prefix/,
		);
	});

	it("refuses a lifetime that does not parse, at construction", () => {
		expect(
			() => new AccessTokensProvider({ store, expiresIn: "soon" }),
		).toThrow(/invalid duration/);
	});
});
