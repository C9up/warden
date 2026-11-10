/**
 * Warden NAPI loader — loads the `warden-engine-napi` binary for Rust-native
 * JWT/HMAC/random operations. There is no TS fallback: when the binary is
 * absent, `nativeWarden()` returns `undefined` and `JwtStrategy` (and any
 * other consumer) throws `E_WARDEN_NAPI_REQUIRED` at use time. Password
 * hashing is the sole responsibility of `@c9up/sigil` (story 40.1).
 */
import { hasFunctions, loadNativeBinary } from "./vendor/nativeBinary.js";

/**
 * What this package calls on the engine, typed as the Rust declares it.
 *
 * Derived from `./native/generated.js` — written by `pnpm build:napi-types`
 * from napi-derive's own `type-def` output — rather than restated here, where
 * nothing would notice a `pub fn` gaining a parameter or changing its return.
 */
const NATIVE_CALLS = ["jwtSign", "jwtVerify"] as const;

export type NativeWarden = Pick<
	typeof import("./native/generated.js"),
	(typeof NATIVE_CALLS)[number]
>;

/** What the package calls, checked at load: a stale binary loads just as well. */
function isNativeWarden(value: unknown): value is NativeWarden {
	return hasFunctions(value, NATIVE_CALLS);
}

// Absent is not an error here: `JwtStrategy` throws E_WARDEN_NAPI_REQUIRED at
// use time, which names what the caller was trying to do. The loader reports
// what happened and this decides — the platform table itself is shared, since
// a package that misses a new target fails only on that platform.
const attempt = loadNativeBinary(isNativeWarden);
const native = attempt.loaded ? attempt.binary : undefined;
const loadError = attempt.loaded ? undefined : attempt.cause;

/** Get the native engine. Returns undefined if not loaded — caller must throw. */
export function nativeWarden(): NativeWarden | undefined {
	return native;
}

/** Why the engine is not loaded, for the `cause` of the error a caller throws. */
export function nativeWardenLoadError(): unknown {
	return loadError;
}
