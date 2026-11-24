/**
 * Warden NAPI loader — loads the `warden-engine-napi` binary for Rust-native
 * JWT/HMAC/random operations. There is no TS fallback: when the binary is
 * absent, `nativeWarden()` returns `undefined` and `JwtStrategy` (and any
 * other consumer) throws `E_WARDEN_NAPI_REQUIRED` at use time. Password
 * hashing is the sole responsibility of `@c9up/sigil` (story 40.1).
 */
import { arch, platform } from "node:process";
import {
	hasFunctions,
	loadNativeBinary,
	muslHint,
	supportedTargets,
} from "./vendor/nativeBinary.js";

/**
 * The npm name the platform packages derive from: `@c9up/warden-<suffix>`,
 * one per target, each an optional dependency pinned to this version.
 */
const PACKAGE_NAME = "@c9up/warden";

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
const attempt = loadNativeBinary(isNativeWarden, NATIVE_CALLS, {
	packageName: PACKAGE_NAME,
});
const native = attempt.loaded ? attempt.binary : undefined;
/** Why the engine is not loaded, kept for the refusal that follows. */
const failure: { fix: string; cause?: unknown } = attempt.loaded
	? { fix: "the engine is loaded." }
	: {
			fix: remedy(attempt.suffix, attempt.platformPackage),
			cause: attempt.cause,
		};

/**
 * What to do about a missing engine, phrased for whoever has to fix it.
 *
 * An application installs the platform package; a checkout of warden builds
 * the local binary. The load error itself is not in here: it names paths on
 * the host, so it travels as the refusal's `cause` instead of its message.
 */
function remedy(
	suffix: string | undefined,
	platformPackage: string | undefined,
): string {
	if (suffix === undefined) {
		return `no prebuilt binary for ${platform}-${arch}; warden ships one for ${supportedTargets().join(", ")}.`;
	}
	if (platformPackage === undefined) {
		return `index.${suffix}.node failed to load. Rebuild it: cd packages/warden && pnpm build:napi`;
	}
	return (
		`install ${platformPackage} at the exact version of ${PACKAGE_NAME}: it is the optional dependency that carries the ${suffix} binary, ` +
		"and an install that omits optional dependencies skips it. " +
		`In a checkout of warden, build it instead: pnpm build:napi.${muslHint()}`
	);
}

/** Get the native engine. Returns undefined if not loaded — caller must throw. */
export function nativeWarden(): NativeWarden | undefined {
	return native;
}

/**
 * Why the engine is not loaded: the fix the caller's error prints and the load
 * error for its `cause`. Only meaningful while `nativeWarden()` is undefined.
 */
export function nativeWardenUnavailable(): { fix: string; cause?: unknown } {
	return failure;
}
