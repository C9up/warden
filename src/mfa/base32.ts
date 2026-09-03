/**
 * RFC 4648 base32 (no padding) — the encoding authenticator apps expect for
 * TOTP secrets. Kept dependency-free and local to the MFA subsystem.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CHAR_TO_VAL: Record<string, number> = {};
for (const [i, char] of [...ALPHABET].entries()) {
	CHAR_TO_VAL[char] = i;
}

/** Encode bytes to an unpadded, uppercase base32 string. */
export function base32Encode(bytes: Uint8Array): string {
	let bits = 0;
	let value = 0;
	let out = "";
	for (const byte of bytes) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			out += ALPHABET[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if (bits > 0) {
		out += ALPHABET[(value << (5 - bits)) & 31];
	}
	return out;
}

/**
 * Decode a base32 string to bytes. Tolerant of lowercase, spaces, and `=`
 * padding (authenticator apps and manual entry produce all three). Throws on
 * any character outside the alphabet.
 */
export function base32Decode(input: string): Uint8Array {
	const clean = input.replace(/[\s=]/g, "").toUpperCase();
	let bits = 0;
	let value = 0;
	const out: number[] = [];
	for (const ch of clean) {
		const v = CHAR_TO_VAL[ch];
		if (v === undefined) {
			throw new Error(`Invalid base32 character: ${ch}`);
		}
		value = (value << 5) | v;
		bits += 5;
		if (bits >= 8) {
			out.push((value >>> (bits - 8)) & 0xff);
			bits -= 8;
		}
	}
	return Uint8Array.from(out);
}
