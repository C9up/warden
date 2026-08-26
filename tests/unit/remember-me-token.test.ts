/**
 * Remember-me tokens. The shape follows `@adonisjs/auth`'s RememberMeToken:
 * the cookie is `base64url(identifier).base64url(secret)`, the database keeps
 * only `sha256(secret)`, and authenticating recycles the secret.
 *
 * These tests are about the security properties, not the happy path — a
 * persistent credential that is wrong is worse than none at all.
 */
import { describe, expect, it } from "vitest";
import {
	decodeTokenValue,
	encodeTokenValue,
	hashSecret,
	MemoryRememberMeTokenDriver,
	mintRememberMeToken,
	RememberMeToken,
	safeCompareHashes,
	verifyAndRecycleRememberMeToken,
} from "../../src/RememberMeToken.js";
import { Secret } from "../../src/Secret.js";

async function seeded(ageSeconds = 3600) {
	const driver = new MemoryRememberMeTokenDriver();
	const minted = mintRememberMeToken("user-1", ageSeconds);
	await driver.create(minted.stored);
	return { driver, minted };
}

describe("warden > remember-me tokens", () => {
	it("authenticates a valid cookie and returns the user", async () => {
		const { driver, minted } = await seeded();

		const result = await verifyAndRecycleRememberMeToken(
			driver,
			minted.value,
			3600,
		);

		expect(result?.userId).toBe("user-1");
	});

	it("never stores the secret, only its hash", async () => {
		const { driver, minted } = await seeded();
		const decoded = decodeTokenValue(minted.value);
		const row = await driver.find(decoded?.identifier ?? "");

		// A dump of this table must not let anyone sign in.
		expect(row?.hash).toBe(hashSecret(decoded?.secret ?? ""));
		expect(JSON.stringify(row)).not.toContain(decoded?.secret ?? "@@");
	});

	it("recycles the secret on every use, killing the previous cookie", async () => {
		const { driver, minted } = await seeded();

		const first = await verifyAndRecycleRememberMeToken(
			driver,
			minted.value,
			3600,
		);
		expect(first).not.toBeNull();

		// The value the browser was holding is now dead: this is what limits the
		// damage of a stolen cookie.
		expect(
			await verifyAndRecycleRememberMeToken(driver, minted.value, 3600),
		).toBeNull();

		// And the freshly issued one works.
		expect(
			await verifyAndRecycleRememberMeToken(driver, first?.value, 3600),
		).not.toBeNull();
	});

	it("keeps the identifier across a recycle, so the row is reused", async () => {
		const { driver, minted } = await seeded();
		const before = decodeTokenValue(minted.value)?.identifier;

		const recycled = await verifyAndRecycleRememberMeToken(
			driver,
			minted.value,
			3600,
		);

		expect(decodeTokenValue(recycled?.value)?.identifier).toBe(before);
	});

	it("refuses an expired token and removes the row", async () => {
		const driver = new MemoryRememberMeTokenDriver();
		const minted = mintRememberMeToken("user-1", -1);
		await driver.create(minted.stored);

		expect(
			await verifyAndRecycleRememberMeToken(driver, minted.value, 3600),
		).toBeNull();
		// Not left behind for a cleanup job that may never run.
		expect(await driver.find(minted.stored.identifier)).toBeNull();
	});

	it("refuses a forged secret against a real identifier", async () => {
		const { driver, minted } = await seeded();
		const identifier = decodeTokenValue(minted.value)?.identifier ?? "";
		const forged = encodeTokenValue(identifier, "not-the-secret");

		expect(
			await verifyAndRecycleRememberMeToken(driver, forged, 3600),
		).toBeNull();
	});

	it("refuses an unknown identifier the same way as a bad secret", async () => {
		const { driver } = await seeded();
		const unknown = encodeTokenValue("no-such-row", "whatever");

		// Same null, no distinguishable error: telling them apart would let an
		// attacker enumerate which identifiers exist.
		expect(
			await verifyAndRecycleRememberMeToken(driver, unknown, 3600),
		).toBeNull();
	});

	it("refuses malformed cookie values without throwing", async () => {
		const { driver } = await seeded();
		for (const value of [
			"",
			"nodot",
			".",
			"a.",
			".b",
			null,
			undefined,
			42,
			"!!!.!!!",
		]) {
			expect(
				await verifyAndRecycleRememberMeToken(driver, value, 3600),
			).toBeNull();
		}
	});

	it("mints a different secret and identifier every time", () => {
		const a = mintRememberMeToken("user-1", 3600);
		const b = mintRememberMeToken("user-1", 3600);

		expect(a.value).not.toBe(b.value);
		expect(a.stored.identifier).not.toBe(b.stored.identifier);
		// A guessable identifier would let someone target one user's row.
		expect(a.stored.identifier).toMatch(/^[0-9a-f]{32}$/);
	});

	it("compares hashes without an early exit on length", () => {
		expect(safeCompareHashes("abc", "abc")).toBe(true);
		expect(safeCompareHashes("abc", "abd")).toBe(false);
		expect(safeCompareHashes("abc", "abcd")).toBe(false);
		expect(safeCompareHashes("", "")).toBe(true);
	});

	it("deleteAllForUser drops every token of that user only", async () => {
		const driver = new MemoryRememberMeTokenDriver();
		const mine = mintRememberMeToken("user-1", 3600);
		const other = mintRememberMeToken("user-2", 3600);
		await driver.create(mine.stored);
		await driver.create(other.stored);

		await driver.deleteAllForUser("user-1");

		expect(await driver.find(mine.stored.identifier)).toBeNull();
		expect(await driver.find(other.stored.identifier)).not.toBeNull();
	});
});

describe("warden > RememberMeToken class (AdonisJS surface)", () => {
	it("decodes a value the functional API produced", () => {
		const minted = mintRememberMeToken("42", 3600);
		const decoded = RememberMeToken.decode(minted.value);

		// One encoding, two APIs: they cannot disagree about what a token is.
		expect(decoded).not.toBe(null);
		expect(decoded?.identifier).toBe(minted.stored.identifier);
		expect(hashSecret(decoded?.secret.release() ?? "")).toBe(
			minted.stored.hash,
		);
	});

	it("returns null for a malformed value rather than throwing", () => {
		expect(RememberMeToken.decode("garbage")).toBe(null);
		expect(RememberMeToken.decode("")).toBe(null);
	});

	it("keeps a decoded secret out of a log", () => {
		const minted = mintRememberMeToken("42", 3600);
		const secret = RememberMeToken.decode(minted.value)?.secret;

		// Interpolating it must not print the secret — that is the whole point
		// of the wrapper AdonisJS returns here.
		expect(`${secret}`).toBe("[redacted]");
		expect(JSON.stringify({ secret })).toBe('{"secret":"[redacted]"}');
		expect(secret?.release()).not.toBe("[redacted]");
	});

	it("verifies a secret in constant time and rejects a wrong one", () => {
		const { secret, hash } = RememberMeToken.seed();
		const token = new RememberMeToken({
			identifier: "abc",
			tokenableId: "42",
			hash,
			createdAt: new Date(),
			updatedAt: new Date(),
			expiresAt: new Date(Date.now() + 60_000),
		});

		expect(token.verify(secret)).toBe(true);
		expect(token.verify(new Secret("not-it"))).toBe(false);
	});

	it("reports expiry", () => {
		const base = {
			identifier: "abc",
			tokenableId: "42",
			hash: "x",
			createdAt: new Date(),
			updatedAt: new Date(),
		};
		expect(
			new RememberMeToken({
				...base,
				expiresAt: new Date(Date.now() - 1),
			}).isExpired(),
		).toBe(true);
		expect(
			new RememberMeToken({
				...base,
				expiresAt: new Date(Date.now() + 60_000),
			}).isExpired(),
		).toBe(false);
	});

	it("createTransientToken carries everything the store needs", () => {
		const t = RememberMeToken.createTransientToken("42", 40, 3600);

		expect(t.userId).toBe("42");
		expect(hashSecret(t.secret.release())).toBe(t.hash);
		expect(t.expiresAt.getTime()).toBeGreaterThan(Date.now());
	});

	it("round-trips a stored row", () => {
		const minted = mintRememberMeToken("42", 3600);
		const token = RememberMeToken.fromStored(minted.stored);

		expect(token.toStored()).toEqual(minted.stored);
	});

	it("builds the public value when handed the secret", () => {
		const { secret, hash } = RememberMeToken.seed();
		const token = new RememberMeToken({
			identifier: "abc",
			tokenableId: "42",
			hash,
			createdAt: new Date(),
			updatedAt: new Date(),
			expiresAt: new Date(Date.now() + 60_000),
			secret,
		});

		const decoded = RememberMeToken.decode(token.value?.release() ?? "");
		expect(decoded?.identifier).toBe("abc");
		expect(decoded?.secret.release()).toBe(secret.release());
	});
});
