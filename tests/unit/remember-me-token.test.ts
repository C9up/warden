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
	safeCompareHashes,
	verifyAndRecycleRememberMeToken,
} from "../../src/RememberMeToken.js";

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
