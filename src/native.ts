/**
 * Warden NAPI loader — loads the `warden-engine-napi` binary for Rust-native
 * JWT/HMAC/random operations. There is no TS fallback: when the binary is
 * absent, `nativeWarden()` returns `undefined` and `JwtStrategy` (and any
 * other consumer) throws `E_WARDEN_NAPI_REQUIRED` at use time. Password
 * hashing is the sole responsibility of `@c9up/sigil` (story 40.1).
 */
import { loadNativeBinary } from "./vendor/nativeBinary.js";

/**
 * The engine's surface, as the Rust declares it.
 *
 * Derived from `./native/generated.js` — written by `pnpm build:napi-types`
 * from napi-derive's own `type-def` output — rather than restated here, where
 * nothing would notice a `pub fn` gaining a parameter or changing its return.
 */
export type NativeWarden = typeof import("./native/generated.js");

// Absent is not an error here: `JwtStrategy` throws E_WARDEN_NAPI_REQUIRED at
// use time, which names what the caller was trying to do. The loader reports
// what happened and this decides — the platform table itself is shared, since
// a package that misses a new target fails only on that platform.
const attempt = loadNativeBinary<NativeWarden>();
const native = attempt.loaded ? attempt.binary : undefined;

/** Whether the Rust NAPI engine loaded. */
export function isNativeAvailable(): boolean {
	return native !== undefined;
}

/** Get the native engine. Returns undefined if not loaded — caller must throw. */
export function nativeWarden(): NativeWarden | undefined {
	return native;
}
