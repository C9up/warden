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

		expect(await otp.verify(challengeId, channel.last())).toEqual({ ok: true });
		// Consumed — second use fails as not_found.
		expect(await otp.verify(challengeId, channel.last())).toEqual({
			ok: false,
			reason: "not_found",
		});
	});

	it("rejects an expired code", async () => {
		const channel = new CapturingChannel();
		const otp = new OtpProvider({ channel, ttlSeconds: 60 });
		const now = 1_700_000_000_000;
		const { challengeId } = await otp.start("a", now);

		// Inside the window the code is fine; one second past expiry it is not.
		expect((await otp.verify(challengeId, channel.last(), now + 1000)).ok).toBe(
			true,
		);
		const replay = await otp.start("a", now);
		const expired = await otp.verify(
			replay.challengeId,
			channel.last(),
			now + 61_000,
		);
		expect(expired).toEqual({ ok: false, reason: "expired" });
	});

	it("burns the challenge after too many wrong attempts", async () => {
		const channel = new CapturingChannel();
		const otp = new OtpProvider({ channel, maxAttempts: 3 });
		const { challengeId } = await otp.start("a");

		expect((await otp.verify(challengeId, "000000")).reason).toBe("mismatch");
		expect((await otp.verify(challengeId, "000000")).reason).toBe("mismatch");
		// Third wrong attempt exhausts the budget and deletes the challenge.
		expect((await otp.verify(challengeId, "000000")).reason).toBe(
			"too_many_attempts",
		);
		// Even the correct code now fails — challenge is gone.
		expect((await otp.verify(challengeId, channel.last())).reason).toBe(
			"not_found",
		);
	});
});
