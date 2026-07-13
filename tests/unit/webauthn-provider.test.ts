/**
 * WebauthnProvider — full registration + authentication ceremonies driven by a
 * fake authenticator built in-test from a real Node EC P-256 keypair. Node's
 * `crypto.sign` is the independent oracle: it proves the in-house CBOR decoder,
 * authenticator-data parser, COSE→key conversion and signature verification all
 * interoperate, with no third-party WebAuthn library involved.
 */
import {
	createHash,
	sign as cryptoSign,
	generateKeyPairSync,
	type KeyObject,
	randomBytes,
} from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
	type AuthenticationResponseJSON,
	MemoryWebauthnChallengeStore,
	type RegistrationResponseJSON,
	WebauthnProvider,
} from "../../src/mfa/WebauthnProvider.js";

const RP_ID = "fluveo.ch";
const ORIGIN = "https://fluveo.ch";

function b64url(b: Buffer): string {
	return b.toString("base64url");
}
function sha256(b: Buffer): Buffer {
	return createHash("sha256").update(b).digest();
}

// ── minimal CBOR encoder (test oracle, independent of the decoder) ──
function head(major: number, n: number): Buffer {
	if (n < 24) return Buffer.from([(major << 5) | n]);
	if (n < 256) return Buffer.from([(major << 5) | 24, n]);
	if (n < 65536) {
		const b = Buffer.alloc(3);
		b[0] = (major << 5) | 25;
		b.writeUInt16BE(n, 1);
		return b;
	}
	const b = Buffer.alloc(5);
	b[0] = (major << 5) | 26;
	b.writeUInt32BE(n, 1);
	return b;
}
function cInt(n: number): Buffer {
	return n < 0 ? head(1, -1 - n) : head(0, n);
}
function cBytes(b: Buffer): Buffer {
	return Buffer.concat([head(2, b.length), b]);
}
function cText(s: string): Buffer {
	const u = Buffer.from(s, "utf8");
	return Buffer.concat([head(3, u.length), u]);
}
function cMap(entries: Array<[number | string, Buffer]>): Buffer {
	const body = entries.map(([k, v]) =>
		Buffer.concat([typeof k === "number" ? cInt(k) : cText(k), v]),
	);
	return Buffer.concat([head(5, entries.length), ...body]);
}

/** A fake authenticator backed by a real EC P-256 keypair. */
class FakeAuthenticator {
	readonly credentialId = randomBytes(16);
	private readonly privateKey: KeyObject;
	private readonly coseKey: Buffer;

	constructor() {
		const { publicKey, privateKey } = generateKeyPairSync("ec", {
			namedCurve: "P-256",
		});
		this.privateKey = privateKey;
		const jwk = publicKey.export({ format: "jwk" });
		const x = Buffer.from(String(jwk.x), "base64url");
		const y = Buffer.from(String(jwk.y), "base64url");
		this.coseKey = cMap([
			[1, cInt(2)], // kty: EC2
			[3, cInt(-7)], // alg: ES256
			[-1, cInt(1)], // crv: P-256
			[-2, cBytes(x)],
			[-3, cBytes(y)],
		]);
	}

	private authData(
		flags: number,
		signCount: number,
		withCred: boolean,
	): Buffer {
		const parts = [
			sha256(Buffer.from(RP_ID, "utf8")),
			Buffer.from([flags]),
			(() => {
				const c = Buffer.alloc(4);
				c.writeUInt32BE(signCount);
				return c;
			})(),
		];
		if (withCred) {
			const credLen = Buffer.alloc(2);
			credLen.writeUInt16BE(this.credentialId.length);
			parts.push(
				Buffer.alloc(16), // aaguid
				credLen,
				this.credentialId,
				this.coseKey,
			);
		}
		return Buffer.concat(parts);
	}

	register(challenge: string, origin = ORIGIN): RegistrationResponseJSON {
		const clientData = b64url(
			Buffer.from(
				JSON.stringify({ type: "webauthn.create", challenge, origin }),
				"utf8",
			),
		);
		// flags: UP | UV | AT
		const authData = this.authData(0x45, 0, true);
		const attestationObject = cMap([
			["fmt", cText("none")],
			["attStmt", cMap([])],
			["authData", cBytes(authData)],
		]);
		const id = b64url(this.credentialId);
		return {
			id,
			rawId: id,
			type: "public-key",
			response: {
				clientDataJSON: clientData,
				attestationObject: b64url(attestationObject),
				transports: ["internal"],
			},
		};
	}

	authenticate(
		challenge: string,
		signCount: number,
		origin = ORIGIN,
		flags = 0x05,
	): AuthenticationResponseJSON {
		const clientDataRaw = Buffer.from(
			JSON.stringify({ type: "webauthn.get", challenge, origin }),
			"utf8",
		);
		// flags default UP | UV (no attested credential data on assertion);
		// callers pass 0x01 (UP only) to exercise the required-UV rejection.
		const authData = this.authData(flags, signCount, false);
		const signedData = Buffer.concat([authData, sha256(clientDataRaw)]);
		const signature = cryptoSign("sha256", signedData, this.privateKey);
		const id = b64url(this.credentialId);
		return {
			id,
			rawId: id,
			type: "public-key",
			response: {
				clientDataJSON: b64url(clientDataRaw),
				authenticatorData: b64url(authData),
				signature: b64url(signature),
			},
		};
	}
}

function provider(): WebauthnProvider {
	return new WebauthnProvider({
		rpName: "Fluveo",
		rpID: RP_ID,
		origin: ORIGIN,
	});
}

const USER = { id: "user-1", name: "k@c9up.com" };

describe("warden > WebauthnProvider — options", () => {
	it("emits registration options with a challenge, rp id and algorithms", async () => {
		const { options, state } = await provider().startRegistration(USER);
		expect(options.rp.id).toBe(RP_ID);
		expect(options.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(options.pubKeyCredParams.map((p) => p.alg)).toContain(-7);
		expect(options.attestation).toBe("none");
		expect(state).toMatch(/^[0-9a-f]{32}$/);
	});

	it("scopes authentication options to a user's credentials", async () => {
		const p = provider();
		const auth = new FakeAuthenticator();
		const reg = await p.startRegistration(USER);
		await p.finishRegistration(
			reg.state,
			USER.id,
			auth.register(reg.options.challenge),
		);

		const { options } = await p.startAuthentication(USER.id);
		expect(options.allowCredentials).toHaveLength(1);
		expect(options.allowCredentials?.[0].id).toBe(b64url(auth.credentialId));
	});
});

describe("warden > WebauthnProvider — registration", () => {
	it("registers a passkey end-to-end", async () => {
		const p = provider();
		const auth = new FakeAuthenticator();
		const { options, state } = await p.startRegistration(USER);
		const res = await p.finishRegistration(
			state,
			USER.id,
			auth.register(options.challenge),
		);
		expect(res.verified).toBe(true);
	});

	it("rejects a response from the wrong origin", async () => {
		const p = provider();
		const auth = new FakeAuthenticator();
		const { options, state } = await p.startRegistration(USER);
		const res = await p.finishRegistration(
			state,
			USER.id,
			auth.register(options.challenge, "https://evil.example"),
		);
		expect(res.verified).toBe(false);
	});

	it("rejects a tampered challenge", async () => {
		const p = provider();
		const auth = new FakeAuthenticator();
		const { state } = await p.startRegistration(USER);
		const res = await p.finishRegistration(
			state,
			USER.id,
			auth.register(b64url(randomBytes(32))),
		);
		expect(res.verified).toBe(false);
	});

	it("rejects an unknown ceremony state", async () => {
		const p = provider();
		const auth = new FakeAuthenticator();
		const res = await p.finishRegistration(
			"deadbeef",
			USER.id,
			auth.register("whatever"),
		);
		expect(res.verified).toBe(false);
	});
});

describe("warden > WebauthnProvider — authentication", () => {
	async function enroll(): Promise<{
		p: WebauthnProvider;
		auth: FakeAuthenticator;
	}> {
		const p = provider();
		const auth = new FakeAuthenticator();
		const reg = await p.startRegistration(USER);
		await p.finishRegistration(
			reg.state,
			USER.id,
			auth.register(reg.options.challenge),
		);
		return { p, auth };
	}

	it("verifies a valid assertion and returns the user id", async () => {
		const { p, auth } = await enroll();
		const { options, state } = await p.startAuthentication(USER.id);
		const res = await p.finishAuthentication(
			state,
			auth.authenticate(options.challenge, 1),
		);
		expect(res).toEqual({ verified: true, userId: USER.id });
	});

	it("rejects a forged signature", async () => {
		const { p, auth } = await enroll();
		const { options, state } = await p.startAuthentication(USER.id);
		const assertion = auth.authenticate(options.challenge, 1);
		// Flip a byte in the signature.
		const sig = Buffer.from(assertion.response.signature, "base64url");
		sig[sig.length - 1] ^= 0xff;
		assertion.response.signature = sig.toString("base64url");
		const res = await p.finishAuthentication(state, assertion);
		expect(res.verified).toBe(false);
	});

	it("rejects an unknown credential", async () => {
		const { p } = await enroll();
		const stranger = new FakeAuthenticator();
		const { options, state } = await p.startAuthentication(USER.id);
		const res = await p.finishAuthentication(
			state,
			stranger.authenticate(options.challenge, 1),
		);
		expect(res.verified).toBe(false);
	});

	it("rejects a cloned authenticator (counter does not advance)", async () => {
		const { p, auth } = await enroll();
		// First sign-in advances the counter to 5.
		const a1 = await p.startAuthentication(USER.id);
		expect(
			(
				await p.finishAuthentication(
					a1.state,
					auth.authenticate(a1.options.challenge, 5),
				)
			).verified,
		).toBe(true);
		// A replay/clone re-using counter 5 must be refused.
		const a2 = await p.startAuthentication(USER.id);
		const res = await p.finishAuthentication(
			a2.state,
			auth.authenticate(a2.options.challenge, 5),
		);
		expect(res.verified).toBe(false);
	});
});

describe("warden > WebauthnProvider — challenge TTL", () => {
	it("MemoryWebauthnChallengeStore refuses an expired challenge", async () => {
		vi.useFakeTimers();
		try {
			const store = new MemoryWebauthnChallengeStore(1000);
			await store.save("s1", "chal-1");
			vi.advanceTimersByTime(1001);
			expect(await store.take("s1")).toBeNull();

			// A fresh challenge within the TTL is still returned once.
			await store.save("s2", "chal-2");
			expect(await store.take("s2")).toBe("chal-2");
			expect(await store.take("s2")).toBeNull(); // single-use
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("warden > WebauthnProvider — required user verification", () => {
	it("rejects a UP-only assertion but accepts a UV assertion", async () => {
		const p = new WebauthnProvider({
			rpName: "Fluveo",
			rpID: RP_ID,
			origin: ORIGIN,
			userVerification: "required",
		});
		const auth = new FakeAuthenticator();
		const reg = await p.startRegistration(USER);
		await p.finishRegistration(
			reg.state,
			USER.id,
			auth.register(reg.options.challenge),
		);

		// The ceremony options must actually request required UV.
		const a1 = await p.startAuthentication(USER.id);
		expect(a1.options.userVerification).toBe("required");

		// A user-presence-only assertion (flags 0x01, no UV) is rejected.
		const upOnly = await p.finishAuthentication(
			a1.state,
			auth.authenticate(a1.options.challenge, 1, ORIGIN, 0x01),
		);
		expect(upOnly.verified).toBe(false);

		// A UV assertion (flags 0x05) is accepted.
		const a2 = await p.startAuthentication(USER.id);
		const withUv = await p.finishAuthentication(
			a2.state,
			auth.authenticate(a2.options.challenge, 2, ORIGIN, 0x05),
		);
		expect(withUv.verified).toBe(true);
	});
});
