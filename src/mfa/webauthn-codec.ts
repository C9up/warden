/**
 * WebAuthn wire-format codec — the parsing and crypto primitives behind
 * `WebauthnProvider`, implemented from scratch on `node:crypto` so warden
 * carries no third-party dependency.
 *
 * Scope: the subset of CBOR / COSE / authenticator-data that FIDO2 ceremonies
 * actually use, with public-key algorithms Node can import via JWK:
 *   - ES256 / ES384 / ES512 (ECDSA, COSE alg -7 / -35 / -36)
 *   - RS256 / RS384 / RS512 (RSASSA-PKCS1-v1_5, alg -257 / -258 / -259)
 *   - EdDSA / Ed25519 (alg -8)
 *
 * Attestation *statements* are intentionally not verified (see WebauthnProvider).
 */

import {
	createHash,
	createPublicKey,
	verify as cryptoVerify,
	type JsonWebKey,
	type KeyObject,
} from "node:crypto";

export type CborValue =
	| number
	| string
	| Buffer
	| CborValue[]
	| CborMap
	| boolean
	| null;
export type CborMap = Map<number | string, CborValue>;

export function base64urlToBuffer(s: string): Buffer {
	return Buffer.from(s, "base64url");
}

export function bufferToBase64url(b: Buffer | Uint8Array): string {
	return Buffer.from(b).toString("base64url");
}

export function sha256(data: Buffer): Buffer {
	return createHash("sha256").update(data).digest();
}

interface Decoded {
	value: CborValue;
	/** Byte offset immediately after the decoded item. */
	next: number;
}

/**
 * Decode a single CBOR item starting at `start`. Definite-length only —
 * indefinite-length items and floats are rejected (WebAuthn uses neither).
 */
export function decodeCbor(buf: Buffer, start = 0): Decoded {
	const major = buf[start] >> 5;
	const info = buf[start] & 0x1f;
	let len: number;
	let p = start + 1;
	if (info < 24) {
		len = info;
	} else if (info === 24) {
		len = buf[p];
		p += 1;
	} else if (info === 25) {
		len = buf.readUInt16BE(p);
		p += 2;
	} else if (info === 26) {
		len = buf.readUInt32BE(p);
		p += 4;
	} else if (info === 27) {
		len = Number(buf.readBigUInt64BE(p));
		p += 8;
	} else {
		throw new Error("CBOR: indefinite or reserved length is not supported");
	}

	switch (major) {
		case 0: // unsigned int
			return { value: len, next: p };
		case 1: // negative int
			return { value: -1 - len, next: p };
		case 2: // byte string
			return { value: buf.subarray(p, p + len), next: p + len };
		case 3: // text string
			return { value: buf.toString("utf8", p, p + len), next: p + len };
		case 4: {
			// array
			const arr: CborValue[] = [];
			let cur = p;
			for (let i = 0; i < len; i++) {
				const d = decodeCbor(buf, cur);
				arr.push(d.value);
				cur = d.next;
			}
			return { value: arr, next: cur };
		}
		case 5: {
			// map
			const map: CborMap = new Map();
			let cur = p;
			for (let i = 0; i < len; i++) {
				const k = decodeCbor(buf, cur);
				cur = k.next;
				const v = decodeCbor(buf, cur);
				cur = v.next;
				if (typeof k.value !== "number" && typeof k.value !== "string") {
					throw new Error("CBOR: only integer/text map keys are supported");
				}
				map.set(k.value, v.value);
			}
			return { value: map, next: cur };
		}
		case 6: {
			// tag — decode and surface the tagged content
			const d = decodeCbor(buf, p);
			return { value: d.value, next: d.next };
		}
		case 7:
			if (info === 20) return { value: false, next: p };
			if (info === 21) return { value: true, next: p };
			if (info === 22) return { value: null, next: p };
			throw new Error("CBOR: simple/float values are not supported");
		default:
			throw new Error(`CBOR: unknown major type ${major}`);
	}
}

export interface AuthenticatorData {
	rpIdHash: Buffer;
	flags: { up: boolean; uv: boolean; at: boolean; ed: boolean };
	signCount: number;
	credentialId?: Buffer;
	cosePublicKey?: CborMap;
	/** Raw COSE_Key bytes, ready to persist and re-decode at sign-in time. */
	cosePublicKeyBytes?: Buffer;
}

/** Parse the raw authenticator-data structure (§6.1 of the WebAuthn spec). */
export function parseAuthenticatorData(authData: Buffer): AuthenticatorData {
	if (authData.length < 37) {
		throw new Error("authenticatorData is too short");
	}
	const flagsByte = authData[32];
	const flags = {
		up: (flagsByte & 0x01) !== 0,
		uv: (flagsByte & 0x04) !== 0,
		at: (flagsByte & 0x40) !== 0,
		ed: (flagsByte & 0x80) !== 0,
	};
	const result: AuthenticatorData = {
		rpIdHash: authData.subarray(0, 32),
		flags,
		signCount: authData.readUInt32BE(33),
	};
	if (flags.at) {
		if (authData.length < 55) {
			throw new Error("attested credential data is truncated");
		}
		const credIdLen = authData.readUInt16BE(53);
		result.credentialId = authData.subarray(55, 55 + credIdLen);
		const coseStart = 55 + credIdLen;
		const decoded = decodeCbor(authData, coseStart);
		if (!(decoded.value instanceof Map)) {
			throw new Error("COSE public key is not a CBOR map");
		}
		result.cosePublicKey = decoded.value;
		result.cosePublicKeyBytes = authData.subarray(coseStart, decoded.next);
	}
	return result;
}

// COSE algorithm id → the hash Node should use ( `null` = pre-hashed / Ed25519 ).
const ALG_HASH: Record<number, string | null> = {
	[-7]: "sha256",
	[-35]: "sha384",
	[-36]: "sha512",
	[-257]: "sha256",
	[-258]: "sha384",
	[-259]: "sha512",
	[-8]: null,
};

const EC_CURVES: Record<number, string> = {
	1: "P-256",
	2: "P-384",
	3: "P-521",
};

/** Convert a COSE_Key map into a Node public key plus its COSE algorithm id. */
export function coseToKeyObject(cose: CborMap): {
	key: KeyObject;
	alg: number;
} {
	const kty = expectNumber(cose.get(1), "COSE kty");
	const alg = expectNumber(cose.get(3), "COSE alg");
	let jwk: JsonWebKey;

	if (kty === 2) {
		// EC2
		const curve = EC_CURVES[expectNumber(cose.get(-1), "EC curve")];
		if (!curve) {
			throw new Error("unsupported COSE EC curve");
		}
		jwk = {
			kty: "EC",
			crv: curve,
			x: bufferToBase64url(expectBytes(cose.get(-2), "EC x")),
			y: bufferToBase64url(expectBytes(cose.get(-3), "EC y")),
		};
	} else if (kty === 3) {
		// RSA
		jwk = {
			kty: "RSA",
			n: bufferToBase64url(expectBytes(cose.get(-1), "RSA n")),
			e: bufferToBase64url(expectBytes(cose.get(-2), "RSA e")),
		};
	} else if (kty === 1) {
		// OKP / Ed25519
		if (expectNumber(cose.get(-1), "OKP curve") !== 6) {
			throw new Error("unsupported COSE OKP curve (only Ed25519)");
		}
		jwk = {
			kty: "OKP",
			crv: "Ed25519",
			x: bufferToBase64url(expectBytes(cose.get(-2), "OKP x")),
		};
	} else {
		throw new Error(`unsupported COSE key type ${kty}`);
	}

	return { key: createPublicKey({ key: jwk, format: "jwk" }), alg };
}

/**
 * Verify a WebAuthn assertion signature over `data` (= authenticatorData ‖
 * SHA-256(clientDataJSON)). ECDSA signatures are DER-encoded, matching what
 * authenticators emit.
 */
export function verifyWebauthnSignature(
	alg: number,
	key: KeyObject,
	data: Buffer,
	signature: Buffer,
): boolean {
	if (!(alg in ALG_HASH)) {
		throw new Error(`unsupported COSE algorithm ${alg}`);
	}
	return cryptoVerify(ALG_HASH[alg], data, key, signature);
}

function expectNumber(v: CborValue | undefined, what: string): number {
	if (typeof v !== "number") {
		throw new Error(`${what}: expected an integer`);
	}
	return v;
}

function expectBytes(v: CborValue | undefined, what: string): Buffer {
	if (!Buffer.isBuffer(v)) {
		throw new Error(`${what}: expected a byte string`);
	}
	return v;
}
