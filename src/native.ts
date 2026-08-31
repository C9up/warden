/**
 * Warden NAPI loader — loads the `warden-engine-napi` binary for Rust-native
 * JWT/HMAC/random operations. There is no TS fallback: when the binary is
 * absent, `nativeWarden()` returns `undefined` and `JwtStrategy` (and any
 * other consumer) throws `E_WARDEN_NAPI_REQUIRED` at use time. Password
 * hashing is the sole responsibility of `@c9up/sigil` (story 40.1).
 */
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { arch, platform } from "node:process";
import { fileURLToPath } from "node:url";

const nodeRequire = createRequire(import.meta.url);
const currentDir = dirname(fileURLToPath(import.meta.url));

const platformMap: Record<string, string> = {
	"linux-x64": "linux-x64-gnu",
	"linux-arm64": "linux-arm64-gnu",
	"darwin-x64": "darwin-x64",
	"darwin-arm64": "darwin-arm64",
	"win32-x64": "win32-x64-msvc",
};

/**
 * The engine's surface, as the Rust declares it.
 *
 * Derived from `./native/generated.js` — written by `pnpm build:napi-types`
 * from napi-derive's own `type-def` output — rather than restated here, where
 * nothing would notice a `pub fn` gaining a parameter or changing its return.
 */
export type NativeWarden = typeof import("./native/generated.js");

let native: NativeWarden | undefined;

try {
	const suffix = platformMap[`${platform}-${arch}`];
	if (suffix) {
		native = nodeRequire(join(currentDir, `../index.${suffix}.node`));
	}
} catch {
	// Binary not available — JwtStrategy will throw E_WARDEN_NAPI_REQUIRED at use time.
}

/** Whether the Rust NAPI engine loaded. */
export function isNativeAvailable(): boolean {
	return native !== undefined;
}

/** Get the native engine. Returns undefined if not loaded — caller must throw. */
export function nativeWarden(): NativeWarden | undefined {
	return native;
}
