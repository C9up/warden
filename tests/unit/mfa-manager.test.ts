/**
 * MfaManager — TOTP enrollment lifecycle (pending → confirmed), backup-code
 * generation/consumption/regeneration, the unified verify(), and status helpers.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { BackupCodesProvider } from "../../src/mfa/BackupCodesProvider.js";
import { MfaManager } from "../../src/mfa/MfaManager.js";
import { TotpProvider } from "../../src/mfa/TotpProvider.js";

function manager(): MfaManager {
	return new MfaManager({
		issuer: "Fluveo",
		totp: new TotpProvider(),
		backupCodes: new BackupCodesProvider({ count: 5 }),
	});
}

const USER = { id: "user-1", name: "k@c9up.com" };

/**
 * Move past the accept window so the next code is a different one.
 *
 * A TOTP code is single-use (RFC 6238 §5.2), so a test that confirms with a
 * code and then logs in with the SAME one is testing a replay, not a login.
 * Real users type whatever the app shows them a moment later.
 */
function nextTimeStep(): void {
	vi.setSystemTime(Date.now() + 60_000);
}

afterEach(() => {
	vi.useRealTimers();
});

describe("warden > MfaManager — TOTP", () => {
	it("enrolls pending, then confirms with a valid code", async () => {
		const m = manager();
		const totp = new TotpProvider();
		const { factorId, secret, uri } = await m.enrollTotp(USER, "iPhone");
		expect(uri).toContain("otpauth://totp/Fluveo");
		// Pending: not yet enabled and verifyTotp ignores it.
		expect(await m.isEnabled(USER.id)).toBe(false);
		expect(await m.verifyTotp(USER.id, totp.generate(secret))).toBe(false);

		vi.useFakeTimers({ shouldAdvanceTime: true });
		expect(await m.confirmTotp(factorId, totp.generate(secret))).toBe(true);
		expect(await m.isEnabled(USER.id)).toBe(true);
		nextTimeStep();
		expect(await m.verifyTotp(USER.id, totp.generate(secret))).toBe(true);
	});

	it("refuses a code that has already been accepted", async () => {
		const m = manager();
		const totp = new TotpProvider();
		const { factorId, secret } = await m.enrollTotp(USER, "iPhone");
		const code = totp.generate(secret);
		expect(await m.confirmTotp(factorId, code)).toBe(true);
		// Same code, still inside its window — a replay, and refused.
		expect(await m.verifyTotp(USER.id, code)).toBe(false);
	});

	it("does not confirm with a wrong code", async () => {
		const m = manager();
		const { factorId } = await m.enrollTotp(USER);
		expect(await m.confirmTotp(factorId, "000000")).toBe(false);
		expect(await m.isEnabled(USER.id)).toBe(false);
	});
});

describe("warden > MfaManager — backup codes", () => {
	it("generates, verifies once, and regenerates (replacing the old set)", async () => {
		const m = manager();
		const codes = await m.createBackupCodes(USER.id);
		expect(codes).toHaveLength(5);

		expect(await m.verifyBackupCode(USER.id, codes[0])).toBe(true);
		// Consumed.
		expect(await m.verifyBackupCode(USER.id, codes[0])).toBe(false);

		// Regenerate replaces: the remaining old codes stop working.
		const fresh = await m.createBackupCodes(USER.id);
		expect(await m.verifyBackupCode(USER.id, codes[1])).toBe(false);
		expect(await m.verifyBackupCode(USER.id, fresh[0])).toBe(true);

		const summaries = await m.listFactors(USER.id);
		expect(summaries.filter((s) => s.kind === "backup_codes")).toHaveLength(1);
	});
});

describe("warden > MfaManager — unified verify & status", () => {
	it("verify() accepts a TOTP code or a backup code", async () => {
		const m = manager();
		const totp = new TotpProvider();
		const { factorId, secret } = await m.enrollTotp(USER);
		vi.useFakeTimers({ shouldAdvanceTime: true });
		await m.confirmTotp(factorId, totp.generate(secret));
		const codes = await m.createBackupCodes(USER.id);

		nextTimeStep();
		expect(await m.verify(USER.id, totp.generate(secret))).toBe(true);
		expect(await m.verify(USER.id, codes[2])).toBe(true);
		expect(await m.verify(USER.id, "999999")).toBe(false);
	});

	it("listFactors never leaks secrets, and disableFactor removes it", async () => {
		const m = manager();
		const { factorId } = await m.enrollTotp(USER, "Yubikey");
		const [factor] = await m.listFactors(USER.id);
		expect(factor).toEqual({
			id: factorId,
			kind: "totp",
			label: "Yubikey",
			confirmed: false,
		});
		expect(Object.keys(factor)).not.toContain("secret");

		await m.disableFactor(factorId);
		expect(await m.listFactors(USER.id)).toHaveLength(0);
	});

	it("throws when a required provider is missing", async () => {
		const m = new MfaManager({ issuer: "Fluveo" });
		await expect(m.enrollTotp(USER)).rejects.toThrow(/no TotpProvider/);
		await expect(m.createBackupCodes(USER.id)).rejects.toThrow(
			/no BackupCodesProvider/,
		);
	});
});

describe("warden > MfaManager — rate limit", () => {
	async function enrolled(maxAttempts: number) {
		const m = new MfaManager({
			issuer: "Fluveo",
			totp: new TotpProvider(),
			rateLimit: { maxAttempts },
		});
		const totp = new TotpProvider();
		const { factorId, secret } = await m.enrollTotp(USER);
		vi.useFakeTimers({ shouldAdvanceTime: true });
		await m.confirmTotp(factorId, totp.generate(secret));
		// The confirmation code is spent; the tests below log in with a later one.
		nextTimeStep();
		return { m, totp, secret };
	}

	it("locks verify() after too many failures — even a valid code is refused", async () => {
		const { m, totp, secret } = await enrolled(3);
		expect(await m.verify(USER.id, "000000")).toBe(false);
		expect(await m.verify(USER.id, "000001")).toBe(false);
		expect(await m.verify(USER.id, "000002")).toBe(false);
		expect(m.isLocked(USER.id)).toBe(true);
		expect(await m.verify(USER.id, totp.generate(secret))).toBe(false);
	});

	it("a success resets the failure counter", async () => {
		const { m, totp, secret } = await enrolled(3);
		expect(await m.verify(USER.id, "000000")).toBe(false);
		expect(await m.verify(USER.id, "000001")).toBe(false);
		// A valid code succeeds and clears the counter…
		expect(await m.verify(USER.id, totp.generate(secret))).toBe(true);
		expect(m.isLocked(USER.id)).toBe(false);
		// …so two further failures do not lock (would be 4 ≥ 3 without the reset).
		expect(await m.verify(USER.id, "000000")).toBe(false);
		expect(await m.verify(USER.id, "000001")).toBe(false);
		expect(m.isLocked(USER.id)).toBe(false);
	});
});
