/**
 * MfaManager — TOTP enrollment lifecycle (pending → confirmed), backup-code
 * generation/consumption/regeneration, the unified verify(), and status helpers.
 */
import { describe, expect, it } from "vitest";
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

describe("warden > MfaManager — TOTP", () => {
	it("enrolls pending, then confirms with a valid code", async () => {
		const m = manager();
		const totp = new TotpProvider();
		const { factorId, secret, uri } = await m.enrollTotp(USER, "iPhone");
		expect(uri).toContain("otpauth://totp/Fluveo");
		// Pending: not yet enabled and verifyTotp ignores it.
		expect(await m.isEnabled(USER.id)).toBe(false);
		expect(await m.verifyTotp(USER.id, totp.generate(secret))).toBe(false);

		expect(await m.confirmTotp(factorId, totp.generate(secret))).toBe(true);
		expect(await m.isEnabled(USER.id)).toBe(true);
		expect(await m.verifyTotp(USER.id, totp.generate(secret))).toBe(true);
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
		await m.confirmTotp(factorId, totp.generate(secret));
		const codes = await m.createBackupCodes(USER.id);

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
		await m.confirmTotp(factorId, totp.generate(secret));
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
