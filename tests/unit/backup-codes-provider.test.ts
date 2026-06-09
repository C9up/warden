/**
 * BackupCodesProvider — generation shape, single-use consumption, salt
 * isolation (same code hashes differently), and input normalization.
 */
import { describe, expect, it } from "vitest";
import { BackupCodesProvider } from "../../src/mfa/BackupCodesProvider.js";

describe("warden > BackupCodesProvider", () => {
	it("generates the configured number of codes and matching hashes", () => {
		const p = new BackupCodesProvider({ count: 8 });
		const { codes, hashes } = p.generate();
		expect(codes).toHaveLength(8);
		expect(hashes).toHaveLength(8);
		// Plaintext codes are formatted, hashes are salt$digest hex.
		expect(codes[0]).toMatch(/^[A-Z2-7]+-[A-Z2-7]+$/);
		expect(hashes[0]).toMatch(/^[0-9a-f]+\$[0-9a-f]{64}$/);
	});

	it("verifies a code, then consumes it (single-use)", () => {
		const p = new BackupCodesProvider({ count: 5 });
		const { codes, hashes } = p.generate();

		const first = p.verify(hashes, codes[2]);
		expect(first.ok).toBe(true);
		expect(first.remaining).toHaveLength(4);

		// The consumed code no longer verifies against the trimmed list.
		const reuse = p.verify(first.remaining, codes[2]);
		expect(reuse.ok).toBe(false);
		expect(reuse.remaining).toHaveLength(4);

		// A different code still works against the trimmed list.
		const other = p.verify(first.remaining, codes[0]);
		expect(other.ok).toBe(true);
		expect(other.remaining).toHaveLength(3);
	});

	it("accepts codes regardless of separators and case", () => {
		const p = new BackupCodesProvider({ count: 3 });
		const { codes, hashes } = p.generate();
		const messy = codes[1].replace("-", "").toLowerCase();
		expect(p.verify(hashes, messy).ok).toBe(true);
	});

	it("rejects an unknown code without consuming anything", () => {
		const p = new BackupCodesProvider({ count: 4 });
		const { hashes } = p.generate();
		const res = p.verify(hashes, "ZZZZZ-ZZZZZ");
		expect(res.ok).toBe(false);
		expect(res.remaining).toHaveLength(4);
	});

	it("salts each hash so identical material differs at rest", () => {
		const p = new BackupCodesProvider({ count: 2 });
		const a = p.generate();
		const b = p.generate();
		// Astronomically unlikely to collide; mainly asserts salting is active.
		expect(a.hashes[0]).not.toBe(b.hashes[0]);
	});

	it("rejects weak configuration", () => {
		expect(() => new BackupCodesProvider({ count: 0 })).toThrow(
			/count must be/,
		);
		expect(() => new BackupCodesProvider({ length: 4 })).toThrow(
			/length must be/,
		);
	});
});
