/**
 * The JWT blacklist on a quasar connection, against a real server: what is
 * proved is that a revoked token is actually rejected through the connection
 * the rest of the app shares, not through a second socket of warden's own.
 *
 * Skipped, not failed, when no server answers.
 */

import { QuasarManager } from "@c9up/quasar";
import { setQuasar } from "@c9up/quasar/services/main";
import { afterAll, describe, expect, it } from "vitest";
import { quasarConnection } from "../src/quasar.js";
import { RedisBlacklistDriver } from "../src/RedisBlacklistDriver.js";

const url = process.env.REDIS_TEST_URL ?? "redis://127.0.0.1:6379";
const manager = new QuasarManager({
	connection: "main",
	connections: { main: { url, db: 15 } },
});

const live = await manager
	.connection()
	.ping()
	.then(() => true)
	.catch(() => false);

setQuasar(manager);

afterAll(async () => {
	await manager.quit();
});

describe.skipIf(!live)("blacklist on a quasar connection", () => {
	it("revokes a jti through the shared connection", async () => {
		const driver = new RedisBlacklistDriver(quasarConnection("main"), {
			prefix: `warden-test:${process.pid}:`,
		});
		const jti = "token-1";

		expect(await driver.has(jti)).toBe(false);
		await driver.add(jti, Date.now() + 60_000);
		expect(await driver.has(jti)).toBe(true);

		// Visible on the connection the app holds — one socket, not two.
		const raw = await manager
			.connection()
			.get(`warden-test:${process.pid}:${jti}`);
		expect(raw).toBe("1");
	});

	it("does not resolve the connection until a token is checked", async () => {
		const driver = new RedisBlacklistDriver(quasarConnection("main"), {
			prefix: `warden-test:${process.pid}:lazy:`,
		});
		// Constructing it must not dial: an app whose blacklist is never
		// consulted should not open a socket for it.
		expect(driver).toBeInstanceOf(RedisBlacklistDriver);
		expect(await driver.has("never-seen")).toBe(false);
	});

	it("skips a token that is already past its expiry", async () => {
		const driver = new RedisBlacklistDriver(quasarConnection("main"), {
			prefix: `warden-test:${process.pid}:expired:`,
		});
		await driver.add("stale", Date.now() - 1_000);
		expect(await driver.has("stale")).toBe(false);
	});
});
