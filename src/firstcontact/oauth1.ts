/**
 * OAuth 1.0a request signing (RFC 5849), HMAC-SHA1.
 *
 * OAuth1 authenticates each request by signing it, rather than by carrying a
 * bearer token, which is why it needs this at all and OAuth2 does not. The
 * signature covers the method, the URL and every parameter — so getting the
 * base string wrong is the failure mode, and it fails as an opaque 401 from
 * the provider.
 *
 * Everything here is pure: no network, no clock, no randomness. The nonce and
 * timestamp are passed in, which is also what makes the result testable
 * against the vector in the specification.
 */

import { createHmac, randomBytes } from "node:crypto";

/** One parameter. Duplicates of a key are allowed, as the spec permits. */
export type Param = readonly [key: string, value: string];

export interface SignatureInput {
	method: string;
	/** Full URL. Its query string is folded into the signed parameters. */
	url: string;
	/** Parameters beyond the URL query and the `oauth_*` set — a form body. */
	params?: readonly Param[];
	/** The `oauth_*` parameters, without `oauth_signature`. */
	oauth: readonly Param[];
	consumerSecret: string;
	/** Absent on the very first call, when no token exists yet. */
	tokenSecret?: string;
}

/**
 * Percent-encoding as the specification defines it: unreserved characters
 * stay, everything else is uppercase `%XX`.
 *
 * `encodeURIComponent` is close but leaves `!'()*` alone, and a signature
 * computed with those unescaped does not match the one the provider computes.
 */
export function percentEncode(value: string): string {
	return encodeURIComponent(value).replace(
		/[!'()*]/g,
		(character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
	);
}

/** A fresh nonce. Only its uniqueness matters. */
export function nonce(): string {
	return randomBytes(16).toString("hex");
}

/**
 * The signature base string — the exact bytes both sides hash.
 *
 * Query and body parameters are decoded, then re-encoded, then sorted by
 * encoded key and encoded value. That round trip is deliberate: two requests
 * differing only in how they spelled an escape have to produce the same
 * string, or the signature depends on the spelling.
 */
export function signatureBaseString(input: SignatureInput): string {
	const url = new URL(input.url);
	const query: Param[] = [...url.searchParams.entries()].map(
		([key, value]) => [key, value] as Param,
	);

	const encoded = [...query, ...(input.params ?? []), ...input.oauth]
		.map(([key, value]): Param => [percentEncode(key), percentEncode(value)])
		.sort((a, b) => (a[0] === b[0] ? compare(a[1], b[1]) : compare(a[0], b[0])))
		.map(([key, value]) => `${key}=${value}`)
		.join("&");

	// The base URL carries no query, no fragment, and no default port.
	url.search = "";
	url.hash = "";
	const base = url.toString().replace(/\/$/, url.pathname === "/" ? "/" : "");

	return [
		input.method.toUpperCase(),
		percentEncode(base),
		percentEncode(encoded),
	].join("&");
}

/** The signature itself, base64 of HMAC-SHA1 over the base string. */
export function sign(input: SignatureInput): string {
	const key = `${percentEncode(input.consumerSecret)}&${percentEncode(
		input.tokenSecret ?? "",
	)}`;
	return createHmac("sha1", key)
		.update(signatureBaseString(input))
		.digest("base64");
}

/**
 * The `Authorization: OAuth …` header value, signature included.
 *
 * Only the `oauth_*` parameters go in the header; the query and body ones are
 * signed but stay where they were.
 */
export function authorizationHeader(input: SignatureInput): string {
	const signed: Param[] = [
		...input.oauth,
		["oauth_signature", sign(input)] as Param,
	];
	const parts = signed
		.map(([key, value]) => `${percentEncode(key)}="${percentEncode(value)}"`)
		.join(", ");
	return `OAuth ${parts}`;
}

/** The `oauth_*` parameters every signed request carries. */
export function baseOauthParams(options: {
	consumerKey: string;
	token?: string;
	timestamp: number;
	nonce: string;
}): Param[] {
	const params: Param[] = [
		["oauth_consumer_key", options.consumerKey],
		["oauth_nonce", options.nonce],
		["oauth_signature_method", "HMAC-SHA1"],
		["oauth_timestamp", String(options.timestamp)],
		["oauth_version", "1.0"],
	];
	if (options.token) params.push(["oauth_token", options.token]);
	return params;
}

/**
 * Parse a `key=value&…` response body. The token endpoints answer in this
 * form rather than JSON.
 */
export function parseFormBody(body: string): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [key, value] of new URLSearchParams(body).entries()) {
		out[key] = value;
	}
	return out;
}

/** Byte-order comparison, which is what the specification asks for. */
function compare(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}
