/**
 * Resolving the token blacklist's Redis connection out of quasar.
 *
 * quasar is an optional peer: every way the lookup can fail must say which one
 * it was, by code, so an application can tell a missing package from a
 * connection that lacks a command the blacklist issues.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

const SPECIFIER = "@c9up/quasar/services/main";

const load = async () => (await import("../../src/quasar.js")).quasarConnection;

afterEach(() => {
	vi.doUnmock(SPECIFIER);
	vi.resetModules();
});

describe("warden > the quasar bridge", () => {
	it("names the missing package", async () => {
		vi.doMock(SPECIFIER, () => {
			throw new Error("Cannot find module");
		});
		await expect((await load())("main")()).rejects.toMatchObject({
			code: "E_WARDEN_QUASAR_MISSING",
		});
	});

	it("refuses a connection missing a command the blacklist issues", async () => {
		vi.doMock(SPECIFIER, () => ({
			connection: undefined,
			default: { connection: () => ({ set: () => {} }) },
		}));
		await expect((await load())("main")()).rejects.toThrow(
			/connection 'main' is missing exists/,
		);
		await expect((await load())("main")()).rejects.toMatchObject({
			code: "E_WARDEN_INCOMPLETE_CONNECTION",
		});
	});
});
