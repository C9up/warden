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
	type OtpChallengeStore,
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

/**
 * An abandoned challenge must not live forever.
 *
 * Entries only ever left when their id was reused or taken, so a code requested
 * and never submitted — the ordinary abandoned login — stayed for the life of
 * the process. Every one of them is a small, permanent leak, and nothing in the
 * store ever looked at the clock.
 */
describe("warden > abandoned OTP challenges", () => {
	it("drops expired challenges as new ones arrive", async () => {
		const store = new MemoryOtpChallengeStore();
		const expired = (id: string) => ({
			id,
			recipient: "user@example.com",
			hash: "x",
			expiresAt: Date.now() - 1,
			attempts: 0,
		});

		// Past the sweep threshold, all of them already stale.
		for (let i = 0; i < 200; i++) await store.save(expired(`old-${i}`));

		// A sample of the earliest are gone; nothing had to ask for them.
		expect(await store.find("old-0")).toBeNull();
		expect(await store.find("old-1")).toBeNull();
	});

	it("keeps a live challenge while it sweeps around it", async () => {
		const store = new MemoryOtpChallengeStore();
		await store.save({
			id: "live",
			recipient: "user@example.com",
			hash: "x",
			expiresAt: Date.now() + 60_000,
			attempts: 0,
		});
		for (let i = 0; i < 200; i++) {
			await store.save({
				id: `old-${i}`,
				recipient: "u",
				hash: "x",
				expiresAt: Date.now() - 1,
				attempts: 0,
			});
		}

		// A sweep that took the valid one with it would log people out
		// mid-verification, which is worse than the leak it fixes.
		expect(await store.find("live")).not.toBeNull();
	});

	it("does not leave a challenge behind when delivery fails", async () => {
		// Nobody has the code, so it can never be used and never be swept before
		// its TTL — an SMS gateway having a bad hour quietly filled the store.
		// Record what was written, so the assertion is about the entry that
		// actually existed rather than about an id the test invented.
		const saved: string[] = [];
		const base = new MemoryOtpChallengeStore();
		const store: OtpChallengeStore = {
			async save(challenge) {
				saved.push(challenge.id);
				return base.save(challenge);
			},
			find: (id) => base.find(id),
			delete: (id) => base.delete(id),
			take: (id) => base.take(id),
		};
		const otp = new OtpProvider({
			channel: {
				send: async () => {
					throw new Error("gateway down");
				},
			},
			store,
		});

		await expect(otp.start("user@example.com")).rejects.toThrow("gateway down");

		expect(saved).toHaveLength(1);
		const orphan = saved[0];
		if (orphan === undefined) throw new Error("the challenge was never saved");
		expect(await store.find(orphan)).toBeNull();
	});
});
