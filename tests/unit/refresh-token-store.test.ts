import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	decodeRefreshToken,
	MemoryRefreshTokenDriver,
	mintRefreshToken,
	type RefreshTokenDriver,
	type RefreshTokenSuccessor,
	rotateRefreshToken,
	type StoredRefreshToken,
} from "../../src/RefreshTokenStore.js";
import { hashSecret } from "../../src/RememberMeToken.js";

function makeStored(
	overrides: Partial<StoredRefreshToken> = {},
): StoredRefreshToken {
	return {
		familyId: "family-1",
		hash: hashSecret("tok"),
		userId: "user-1",
		expiresAt: Date.now() + 60_000,
		createdAt: Date.now(),
		...overrides,
	};
}

function successor(secret: string): RefreshTokenSuccessor {
	return { hash: hashSecret(secret), expiresAt: Date.now() + 60_000 };
}

/** The value a client holds for `familyId`, given the secret it was handed. */
function tokenValue(familyId: string, secret: string): string {
	const encode = (text: string) => Buffer.from(text).toString("base64url");
	return `${encode(familyId)}.${encode(secret)}`;
}

describe("warden > MemoryRefreshTokenDriver", () => {
	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("returns null for an unknown family", async () => {
		const driver = new MemoryRefreshTokenDriver();
		expect(await driver.find("nope")).toBe(null);
	});

	it("stores and finds a live family by its id", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const family = makeStored({ familyId: "abc", userId: 42 });
		await driver.store(family);
		expect(await driver.find("abc")).toEqual(family);
	});

	it("hands out copies: mutating a found row does not rotate the family", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const family = makeStored();
		await driver.store(family);
		family.hash = hashSecret("forged");
		const found = await driver.find(family.familyId);
		if (found === null) throw new Error("family missing");
		found.hash = hashSecret("forged");
		expect((await driver.find(family.familyId))?.hash).toBe(hashSecret("tok"));
	});

	it("auto-deletes an expired family when find() is called", async () => {
		const driver = new MemoryRefreshTokenDriver();
		await driver.store(makeStored({ expiresAt: Date.now() - 1 }));
		expect(await driver.find("family-1")).toBe(null);
		// Purged, not merely hidden: consume finds nothing to rotate either.
		expect(
			await driver.consume("family-1", hashSecret("tok"), successor("next")),
		).toBe(false);
	});

	it("treats an expiry that is not a number as expired", async () => {
		// `expiresAt < now` is false for NaN: the row never expired.
		const driver = new MemoryRefreshTokenDriver();
		await driver.store(makeStored({ expiresAt: Number.NaN }));
		expect(await driver.find("family-1")).toBe(null);
	});

	it("consume() is a compare-and-set: the current hash rotates once", async () => {
		const driver = new MemoryRefreshTokenDriver();
		await driver.store(makeStored());
		const next = successor("next");

		expect(await driver.consume("family-1", hashSecret("tok"), next)).toBe(
			true,
		);
		// The same presented hash again: already spent.
		expect(
			await driver.consume("family-1", hashSecret("tok"), successor("other")),
		).toBe(false);
		const row = await driver.find("family-1");
		expect(row?.hash).toBe(next.hash);
		expect(row?.expiresAt).toBe(next.expiresAt);
		expect(row?.userId).toBe("user-1");
	});

	it("consume() refuses an unknown family and a hash that is not the current one", async () => {
		const driver = new MemoryRefreshTokenDriver();
		await driver.store(makeStored());
		expect(
			await driver.consume("other", hashSecret("tok"), successor("n")),
		).toBe(false);
		expect(
			await driver.consume("family-1", hashSecret("wrong"), successor("n")),
		).toBe(false);
		expect((await driver.find("family-1"))?.hash).toBe(hashSecret("tok"));
	});

	it("revokeFamily() removes one family only", async () => {
		const driver = new MemoryRefreshTokenDriver();
		await driver.store(makeStored({ familyId: "a" }));
		await driver.store(makeStored({ familyId: "b" }));
		await driver.revokeFamily("a");
		expect(await driver.find("a")).toBe(null);
		expect(await driver.find("b")).not.toBe(null);
	});

	it("revokeAllForUser() removes only the matching user's families", async () => {
		const driver = new MemoryRefreshTokenDriver();
		await driver.store(makeStored({ familyId: "u1-a", userId: "u1" }));
		await driver.store(makeStored({ familyId: "u1-b", userId: "u1" }));
		await driver.store(makeStored({ familyId: "u2-a", userId: "u2" }));
		await driver.revokeAllForUser("u1");
		expect(await driver.find("u1-a")).toBe(null);
		expect(await driver.find("u1-b")).toBe(null);
		expect(await driver.find("u2-a")).not.toBe(null);
	});

	it("revokeAllForUser() matches a numeric id against a string one, both ways", async () => {
		// `1 === "1"` is false: a sign-out-everywhere for user 1 missed the rows
		// a driver had stored with the id as a string, leaving them usable.
		const driver = new MemoryRefreshTokenDriver();
		await driver.store(makeStored({ familyId: "as-string", userId: "1" }));
		await driver.store(makeStored({ familyId: "as-number", userId: 7 }));
		await driver.store(makeStored({ familyId: "other", userId: 2 }));

		await driver.revokeAllForUser(1);
		await driver.revokeAllForUser("7");

		expect(await driver.find("as-string")).toBe(null);
		expect(await driver.find("as-number")).toBe(null);
		expect(await driver.find("other")).not.toBe(null);
	});

	it("cleanup() removes expired families only", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const now = Date.now();
		await driver.store(makeStored({ familyId: "fresh", expiresAt: now + 1 }));
		await driver.store(makeStored({ familyId: "stale", expiresAt: now - 1 }));
		await driver.cleanup();
		expect(await driver.find("fresh")).not.toBe(null);
		expect(await driver.find("stale")).toBe(null);
	});
});

/**
 * A refresh token is a bearer credential: only the hash of its secret is
 * persisted, so a dump of the table is not a set of working tokens.
 */
describe("warden > mintRefreshToken", () => {
	it("opens a family whose row holds only the sha256 of the secret", () => {
		const { value, stored } = mintRefreshToken("u1", 3600);

		const presented = decodeRefreshToken(value);
		expect(presented).toEqual({ familyId: stored.familyId, hash: stored.hash });
		expect(stored.hash).toMatch(/^[0-9a-f]{64}$/);
		expect(stored.familyId).toMatch(/^[0-9a-f]{32}$/);
		const secret = value.split(".")[1] ?? "";
		expect(secret.length).toBeGreaterThan(60);
		expect(JSON.stringify(stored)).not.toContain(secret);
		expect(stored.userId).toBe("u1");
		expect(stored.expiresAt - stored.createdAt).toBe(3_600_000);
	});

	it("opens a new, random family on every sign-in", () => {
		const families = new Set<string>();
		const values = new Set<string>();
		for (let i = 0; i < 50; i++) {
			const minted = mintRefreshToken("u1", 60);
			families.add(minted.stored.familyId);
			values.add(minted.value);
		}
		expect(families.size).toBe(50);
		expect(values.size).toBe(50);
	});

	it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])(
		"refuses a lifetime of %s seconds",
		(ttl) => {
			expect(() => mintRefreshToken("u1", ttl)).toThrow(
				expect.objectContaining({ code: "E_WARDEN_TOKEN_TTL_INVALID" }),
			);
		},
	);
});

describe("warden > decodeRefreshToken", () => {
	it.each([
		undefined,
		42,
		"",
		"no-dot",
		".secret-only",
		// A value minted before families: 64 base64url chars, no family.
		"A".repeat(64),
	])("answers null for %s", (value) => {
		expect(decodeRefreshToken(value)).toBe(null);
	});
});

describe("warden > rotateRefreshToken", () => {
	async function signIn(driver: RefreshTokenDriver, userId = "user-1") {
		const minted = mintRefreshToken(userId, 3600);
		await driver.store(minted.stored);
		return minted;
	}

	it("spends the token presented and answers its successor, in the same family", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const first = await signIn(driver);

		const rotation = await rotateRefreshToken(driver, first.value, 600);
		if (!rotation.rotated) throw new Error("expected a rotation");
		expect(rotation.userId).toBe("user-1");
		expect(rotation.familyId).toBe(first.stored.familyId);
		expect(rotation.value).not.toBe(first.value);
		expect(decodeRefreshToken(rotation.value)?.familyId).toBe(
			first.stored.familyId,
		);

		const row = await driver.find(first.stored.familyId);
		expect(row?.hash).toBe(decodeRefreshToken(rotation.value)?.hash);
		expect(row?.expiresAt).toBe(rotation.expiresAt);
		expect(row?.createdAt).toBe(first.stored.createdAt);
		expect(JSON.stringify(row)).not.toContain(
			rotation.value.split(".")[1] ?? "-",
		);

		// The successor rotates in turn.
		const again = await rotateRefreshToken(driver, rotation.value, 600);
		expect(again.rotated).toBe(true);
	});

	it("two concurrent refreshes with one token yield exactly one pair, and end the family", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const first = await signIn(driver);

		// Both read the row before either writes: the breach can only be read
		// from the outcome of the consume.
		const answers = await Promise.all([
			rotateRefreshToken(driver, first.value, 600),
			rotateRefreshToken(driver, first.value, 600),
		]);

		const won = answers.filter((answer) => answer.rotated);
		const lost = answers.filter((answer) => !answer.rotated);
		expect(won).toHaveLength(1);
		expect(lost).toEqual([
			{
				rotated: false,
				reason: "reused",
				userId: "user-1",
				familyId: first.stored.familyId,
			},
		]);
		// The winner's successor dies with the family: one of the two parties
		// is a thief, and nothing tells which.
		expect(await driver.find(first.stored.familyId)).toBe(null);
		const winner = won[0];
		if (winner === undefined || !winner.rotated) throw new Error("no winner");
		expect(await rotateRefreshToken(driver, winner.value, 600)).toEqual({
			rotated: false,
			reason: "invalid",
		});
	});

	it("a token replayed after its rotation revokes the family it was rotated into", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const first = await signIn(driver);
		const other = await signIn(driver);
		const rotation = await rotateRefreshToken(driver, first.value, 600);
		if (!rotation.rotated) throw new Error("expected a rotation");

		expect(await rotateRefreshToken(driver, first.value, 600)).toEqual({
			rotated: false,
			reason: "reused",
			userId: "user-1",
			familyId: first.stored.familyId,
		});
		// The live descendant is revoked too...
		expect(await rotateRefreshToken(driver, rotation.value, 600)).toEqual({
			rotated: false,
			reason: "invalid",
		});
		// ...and only this sign-in: the user's other family is untouched.
		expect((await rotateRefreshToken(driver, other.value, 600)).rotated).toBe(
			true,
		);
	});

	it("the loser of the consume ends the family even when the winner's write lands between its read and its consume", async () => {
		const memory = new MemoryRefreshTokenDriver();
		const first = await signIn(memory);
		// A store whose read is answered before a concurrent rotation writes.
		let release: () => void = () => {};
		const paused = new Promise<void>((resolve) => {
			release = resolve;
		});
		const slow: RefreshTokenDriver = {
			store: (token) => memory.store(token),
			find: async (familyId) => {
				const row = await memory.find(familyId);
				await paused;
				return row;
			},
			consume: (familyId, hash, next) => memory.consume(familyId, hash, next),
			revokeFamily: (familyId) => memory.revokeFamily(familyId),
			revokeAllForUser: (userId) => memory.revokeAllForUser(userId),
			cleanup: () => memory.cleanup(),
		};

		const late = rotateRefreshToken(slow, first.value, 600);
		const early = await rotateRefreshToken(memory, first.value, 600);
		expect(early.rotated).toBe(true);
		release();
		expect(await late).toMatchObject({ rotated: false, reason: "reused" });
		expect(await memory.find(first.stored.familyId)).toBe(null);
	});

	it("answers invalid, without touching any family, for what is not a live token", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const live = await signIn(driver);
		for (const value of [
			undefined,
			"garbage",
			"A".repeat(64),
			tokenValue("unknown-family", "secret"),
		]) {
			expect(await rotateRefreshToken(driver, value, 600)).toEqual({
				rotated: false,
				reason: "invalid",
			});
		}
		expect(await driver.find(live.stored.familyId)).not.toBe(null);
	});

	it("an expired family is invalid and removed, even from a driver that still returns it", async () => {
		const memory = new MemoryRefreshTokenDriver();
		const minted = mintRefreshToken("user-1", 3600);
		const rows = new Map<string, StoredRefreshToken>([
			[minted.stored.familyId, { ...minted.stored, expiresAt: Date.now() - 1 }],
		]);
		const lax: RefreshTokenDriver = {
			store: (token) => memory.store(token),
			// No expiry filter: the rotation must not rely on the driver's.
			find: async (familyId) => rows.get(familyId) ?? null,
			consume: async () => true,
			revokeFamily: async (familyId) => {
				rows.delete(familyId);
			},
			revokeAllForUser: async () => {},
			cleanup: async () => {},
		};
		expect(await rotateRefreshToken(lax, minted.value, 600)).toEqual({
			rotated: false,
			reason: "invalid",
		});
		expect(rows.size).toBe(0);
	});

	it("a forged secret on a live family ends it: it is not the current token", async () => {
		const driver = new MemoryRefreshTokenDriver();
		const first = await signIn(driver);
		const forged = tokenValue(first.stored.familyId, "not-the-secret");
		expect(await rotateRefreshToken(driver, forged, 600)).toMatchObject({
			rotated: false,
			reason: "reused",
		});
		expect(await driver.find(first.stored.familyId)).toBe(null);
	});

	it("refuses a store that cannot rotate atomically", async () => {
		const memory = new MemoryRefreshTokenDriver();
		const first = await signIn(memory);
		const legacy = {
			store: (token: StoredRefreshToken) => memory.store(token),
			find: (familyId: string) => memory.find(familyId),
			revoke: async () => {},
			revokeAllForUser: async () => {},
			cleanup: async () => {},
		};
		for (const driver of [
			legacy,
			{ ...legacy, consume: async () => true },
			{ ...legacy, revokeFamily: async () => {} },
		]) {
			await expect(
				// A store written against the previous contract, as a plain
				// JavaScript caller would pass it.
				Reflect.apply(rotateRefreshToken, undefined, [
					driver,
					first.value,
					600,
				]),
			).rejects.toMatchObject({ code: "E_WARDEN_REFRESH_STORE_CONTRACT" });
		}
		// Nothing was spent.
		expect((await memory.find(first.stored.familyId))?.hash).toBe(
			first.stored.hash,
		);
	});

	it.each([0, Number.NaN])(
		"refuses a successor lifetime of %s",
		async (ttl) => {
			const driver = new MemoryRefreshTokenDriver();
			const first = await signIn(driver);
			await expect(
				rotateRefreshToken(driver, first.value, ttl),
			).rejects.toMatchObject({ code: "E_WARDEN_TOKEN_TTL_INVALID" });
			expect((await rotateRefreshToken(driver, first.value, 60)).rotated).toBe(
				true,
			);
		},
	);
});
