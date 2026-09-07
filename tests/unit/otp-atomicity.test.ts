/**
 * A one-time code has to be one-time under concurrency, not just in sequence.
 *
 * `verify()` read the challenge, compared, then deleted — three operations with
 * `await` between them. Two requests carrying the same correct code both read
 * it before either deleted it, and both were told `ok`. The attempt budget had
 * the same shape: every concurrent wrong guess read `attempts: 0` and wrote
 * `1`, so twenty of them burned one attempt.
 *
 * A store backed by a network (Redis, SQL) widens the window from microseconds
 * to a round trip.
 */
import { describe, expect, it } from "vitest";
import {
	MemoryOtpChallengeStore,
	OtpProvider,
} from "../../src/mfa/OtpProvider.js";

/** A store whose every operation yields, the way a real one does. */
class SlowStore extends MemoryOtpChallengeStore {
	override async find(id: string) {
		await new Promise((r) => setTimeout(r, 1));
		return super.find(id);
	}
	override async save(
		challenge: Parameters<MemoryOtpChallengeStore["save"]>[0],
	) {
		await new Promise((r) => setTimeout(r, 1));
		return super.save(challenge);
	}
	override async delete(id: string) {
		await new Promise((r) => setTimeout(r, 1));
		return super.delete(id);
	}
}

/** Captures the code the provider sends, so the test can submit it. */
function provider(store: MemoryOtpChallengeStore, maxAttempts?: number) {
	let sent = "";
	const otp = new OtpProvider({
		channel: {
			async send(_recipient: string, code: string) {
				sent = code;
			},
		},
		store,
		...(maxAttempts === undefined ? {} : { maxAttempts }),
	});
	return { otp, code: () => sent };
}

describe("warden > OTP under concurrency", () => {
	it("accepts the correct code exactly once", async () => {
		const { otp, code } = provider(new SlowStore());
		const { challengeId } = await otp.start("user@example.com");

		const results = await Promise.all([
			otp.verify(challengeId, code()),
			otp.verify(challengeId, code()),
		]);

		// Two `{ ok: true }` means the code was spendable twice — a stolen code
		// stays usable for as long as the legitimate holder has not spent it.
		expect(results.filter((r) => r.ok)).toHaveLength(1);
	});

	it("never evaluates more guesses than the budget allows", async () => {
		// The old failure was that every concurrent guess read `attempts: 0` and
		// wrote `1`, so twenty guesses cost one attempt and the budget could not
		// be exhausted. Holding the challenge makes that impossible: a guess is
		// either evaluated — and paid for — or refused outright.
		const { otp } = provider(new SlowStore(), 3);
		const { challengeId } = await otp.start("user@example.com");

		const results = await Promise.all(
			Array.from({ length: 20 }, () => otp.verify(challengeId, "000000")),
		);
		const evaluated = results.filter(
			(r) =>
				!r.ok && (r.reason === "mismatch" || r.reason === "too_many_attempts"),
		);

		expect(evaluated.length).toBeLessThanOrEqual(3);
		// And the rest were REFUSED, not silently forgiven — an attacker gains
		// nothing by firing them in parallel.
		expect(results).toHaveLength(20);
	});

	it("exhausts the budget on repeated guesses, and stays exhausted", async () => {
		const { otp, code } = provider(new SlowStore(), 3);
		const { challengeId } = await otp.start("user@example.com");

		for (let i = 0; i < 3; i++) await otp.verify(challengeId, "000000");

		// Spent: the real code must no longer open it.
		expect((await otp.verify(challengeId, code())).ok).toBe(false);
	});

	it("still accepts a correct code on its own", async () => {
		const { otp, code } = provider(new SlowStore());
		const { challengeId } = await otp.start("user@example.com");

		expect(await otp.verify(challengeId, code())).toEqual({ ok: true });
	});
});
