/**
 * OtpProvider — delivery, happy-path verify, single-use consumption, expiry,
 * and the attempt budget. Uses a capturing in-memory channel.
 */
import { describe, expect, it } from "vitest";
import {
	type OtpDeliveryChannel,
	OtpProvider,
} from "../../src/mfa/OtpProvider.js";

class CapturingChannel implements OtpDeliveryChannel {
	sent: Array<{ recipient: string; code: string }> = [];
	async send(recipient: string, code: string): Promise<void> {
		this.sent.push({ recipient, code });
	}
	last(): string {
		const last = this.sent.at(-1);
		if (last === undefined) throw new Error("no code was sent");
		return last.code;
	}
}

describe("warden > OtpProvider", () => {
	it("rejects an out-of-range numeric config at construction", () => {
		const channel = new CapturingChannel();
		expect(() => new OtpProvider({ channel, digits: 2 })).toThrow(
			/digits must be an integer 4-10/,
		);
		expect(() => new OtpProvider({ channel, digits: 12 })).toThrow(
			/digits must be an integer 4-10/,
		);
		expect(() => new OtpProvider({ channel, ttlSeconds: 0 })).toThrow(
			/ttlSeconds must be a positive integer/,
		);
		expect(() => new OtpProvider({ channel, maxAttempts: 0 })).toThrow(
			/maxAttempts must be a positive integer/,
		);
	});

	it("mints a code, delivers it, and verifies it once", async () => {
		const channel = new CapturingChannel();
		const otp = new OtpProvider({ channel, digits: 6 });

		const { challengeId } = await otp.start("k@c9up.com");
		expect(channel.sent).toHaveLength(1);
		expect(channel.sent[0]?.recipient).toBe("k@c9up.com");
		expect(channel.last()).toMatch(/^\d{6}$/);

		expect(await otp.verify(challengeId, "k@c9up.com", channel.last())).toEqual(
			{ ok: true },
		);
		// Consumed — second use fails as not_found.
		expect(await otp.verify(challengeId, "k@c9up.com", channel.last())).toEqual(
			{
				ok: false,
				reason: "not_found",
			},
		);
	});

	it("rejects an expired code", async () => {
		const channel = new CapturingChannel();
		const otp = new OtpProvider({ channel, ttlSeconds: 60 });
		const now = 1_700_000_000_000;
		const { challengeId } = await otp.start("a", now);

		// Inside the window the code is fine; one second past expiry it is not.
		expect(
			(await otp.verify(challengeId, "a", channel.last(), now + 1000)).ok,
		).toBe(true);
		const replay = await otp.start("a", now);
		const expired = await otp.verify(
			replay.challengeId,
			"a",
			channel.last(),
			now + 61_000,
		);
		expect(expired).toEqual({ ok: false, reason: "expired" });
	});

	it("burns the challenge after too many wrong attempts", async () => {
		const channel = new CapturingChannel();
		const otp = new OtpProvider({ channel, maxAttempts: 3 });
		const { challengeId } = await otp.start("a");

		expect((await otp.verify(challengeId, "a", "000000")).reason).toBe(
			"mismatch",
		);
		expect((await otp.verify(challengeId, "a", "000000")).reason).toBe(
			"mismatch",
		);
		// Third wrong attempt exhausts the budget and deletes the challenge.
		expect((await otp.verify(challengeId, "a", "000000")).reason).toBe(
			"too_many_attempts",
		);
		// Even the correct code now fails — challenge is gone.
		expect((await otp.verify(challengeId, "a", channel.last())).reason).toBe(
			"not_found",
		);
	});

	it("binds a challenge to its recipient: another account's code does not pass", async () => {
		const channel = new CapturingChannel();
		const otp = new OtpProvider({ channel, maxAttempts: 2 });
		const victim = await otp.start("victim@example.com");
		const victimCode = channel.last();
		// The attacker opens a challenge for an address it owns and reads it.
		const own = await otp.start("attacker@example.com");
		const ownCode = channel.last();

		// The victim's second-factor step, handed the attacker's id and code.
		expect(
			await otp.verify(own.challengeId, "victim@example.com", ownCode),
		).toEqual({ ok: false, reason: "not_found" });
		// And the victim's id, presented for another recipient, twice: more
		// than the budget, yet none of the owner's attempts is spent.
		for (let i = 0; i < 3; i++) {
			expect(
				await otp.verify(
					victim.challengeId,
					"attacker@example.com",
					victimCode,
				),
			).toEqual({ ok: false, reason: "not_found" });
		}

		// Both challenges are intact for their real owners.
		expect(
			await otp.verify(victim.challengeId, "victim@example.com", "000000"),
		).toEqual({ ok: false, reason: "mismatch" });
		expect(
			await otp.verify(victim.challengeId, "victim@example.com", victimCode),
		).toEqual({ ok: true });
		expect(
			await otp.verify(own.challengeId, "attacker@example.com", ownCode),
		).toEqual({ ok: true });
	});

	it("refuses a call without the recipient, before touching the challenge", async () => {
		const channel = new CapturingChannel();
		const otp = new OtpProvider({ channel });
		const { challengeId } = await otp.start("a@example.com");
		// The two-argument form of a JavaScript caller.
		await expect(
			Reflect.apply(otp.verify, otp, [challengeId, channel.last()]),
		).rejects.toMatchObject({ code: "E_WARDEN_INVALID_CONFIG" });
		expect(
			await otp.verify(challengeId, "a@example.com", channel.last()),
		).toEqual({ ok: true });
	});
});
