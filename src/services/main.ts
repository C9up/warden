/**
 * Default `AuthManager` singleton — mirror of Adonis's
 * `import auth from '@adonisjs/auth/services/main'` shape.
 *
 *   import auth from '@c9up/warden/services/main'
 *
 *   const result = await auth.verify(bearerToken)
 *   if (result.authenticated) { ... }
 *
 * Populated by `WardenProvider.boot()`.
 */

import type { AuthManager } from "../AuthManager.js";
import { WardenError } from "../errors.js";

let instance: AuthManager | undefined;

/** @internal Bind the singleton (called by WardenProvider). */
export function setAuth(value: AuthManager): void {
	instance = value;
}

/** @internal Read the singleton (or `undefined` pre-boot). */
export function getAuth(): AuthManager | undefined {
	return instance;
}

/**
 * @internal Release the singleton, so a shut-down application does not leave a
 * dead AuthManager reachable through `services/main`.
 *
 * The caller checks ownership first (`getAuth() === mine`). Two applications in
 * one process share this module, and the one shutting down must not clear a
 * manager the other has since installed — for auth, that would leave the
 * survivor authenticating against nothing, or throwing on every guarded route.
 */
export function clearAuth(): void {
	instance = undefined;
}

// The target is never read through — every trap forwards to `instance`.
const target: AuthManager = Object.create(null);

const auth: AuthManager = new Proxy(target, {
	get(_target, prop) {
		// Whatever inspects a value before using it reads `then` (a promise or an
		// async factory resolving with it decides whether it is thenable) and
		// symbols (inspection, coercion, module interop). None is a member of
		// AuthManager, so answer undefined and let a genuine access report.
		if (typeof prop === "symbol" || prop === "then") {
			return undefined;
		}
		if (!instance) {
			throw new WardenError(
				"NOT_BOOTED",
				"[warden] AuthManager singleton accessed before WardenProvider.boot() ran. " +
					"Check that `@c9up/warden/provider` is listed in your reamrc.ts providers.",
			);
		}
		const value = Reflect.get(instance, prop, instance);
		return typeof value === "function" ? value.bind(instance) : value;
	},
});

export default auth;
