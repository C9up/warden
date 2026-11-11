/**
 * Read the token out of an `Authorization: Bearer <token>` header.
 *
 * The scheme is matched case-insensitively (RFC 7235: auth-schemes are
 * case-insensitive), so `bearer` and `BEARER` are the same credential, as
 * `Basic` already was. Split on the first spaces like the reference guard:
 * the scheme, then the token; a header with no token is no credential.
 *
 * @returns The token, or `""` when the header carries no bearer credential.
 */
export function readBearerToken(header: unknown): string {
	if (typeof header !== "string") return "";
	const [type, token] = header.split(" ");
	if (type?.toLowerCase() !== "bearer" || !token) return "";
	return token;
}
