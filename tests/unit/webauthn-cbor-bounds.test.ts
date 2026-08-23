/**
 * A WebAuthn registration payload is whatever the browser posted, so the CBOR
 * decoder is an attacker-facing parser. It had no depth limit and believed
 * declared lengths: 200 KB of tag bytes overflowed the stack, and a 5-byte
 * payload claiming a 4-billion-item array burned seconds of event loop.
 */
import { describe, expect, it } from "vitest";
import { decodeCbor } from "../../src/mfa/webauthn-codec.js";

describe("warden > CBOR bounds", () => {
	it("refuses runaway nesting instead of overflowing the stack", () => {
		expect(() => decodeCbor(Buffer.alloc(200_000, 0xc0))).toThrow(
			/nesting deeper than/,
		);
	});

	it("refuses an array longer than the bytes that are left", () => {
		// 0x9a = array, 32-bit count; then 0xffffffff items in 0 remaining bytes.
		const hostile = Buffer.from([0x9a, 0xff, 0xff, 0xff, 0xff]);
		const started = performance.now();
		expect(() => decodeCbor(hostile)).toThrow(/exceeds the remaining bytes/);
		expect(performance.now() - started).toBeLessThan(50);
	});

	it("refuses a map longer than the bytes that are left", () => {
		const hostile = Buffer.from([0xba, 0xff, 0xff, 0xff, 0xff]);
		expect(() => decodeCbor(hostile)).toThrow(/exceeds the remaining bytes/);
	});

	it("refuses a byte string that runs past the end", () => {
		expect(() =>
			decodeCbor(Buffer.from([0x5a, 0x00, 0x10, 0x00, 0x00])),
		).toThrow(/exceeds the remaining bytes/);
	});

	it("refuses a 64-bit length no buffer could hold", () => {
		const hostile = Buffer.concat([
			Buffer.from([0x5b]),
			Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
		]);
		expect(() => decodeCbor(hostile)).toThrow(/safe integer range/);
	});

	it("refuses a truncated length header", () => {
		expect(() => decodeCbor(Buffer.from([0x19, 0x00]))).toThrow(/truncated/);
	});

	it("refuses to start past the end", () => {
		expect(() => decodeCbor(Buffer.from([0x01]), 5)).toThrow(/past the end/);
	});

	it("still decodes what WebAuthn actually sends", () => {
		// { 1: "a", 2: h'0102' } — the shape an attestation object carries.
		const payload = Buffer.from([
			0xa2, 0x01, 0x61, 0x61, 0x02, 0x42, 0x01, 0x02,
		]);
		const decoded = decodeCbor(payload).value;
		expect(decoded).toBeInstanceOf(Map);
		const map = decoded as Map<number, unknown>;
		expect(map.get(1)).toBe("a");
		expect(Buffer.from(map.get(2) as Uint8Array)).toEqual(
			Buffer.from([0x01, 0x02]),
		);
	});

	it("accepts nesting a real payload uses", () => {
		// [[[1]]] — three levels, well inside the limit.
		expect(decodeCbor(Buffer.from([0x81, 0x81, 0x81, 0x01])).value).toEqual([
			[[1]],
		]);
	});
});
