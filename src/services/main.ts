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

let _instance: AuthManager | undefined;

/** @internal Bind the singleton (called by WardenProvider). */
export function _setAuth(instance: AuthManager): void {
	_instance = instance;
}

/** @internal Read the singleton (or `undefined` pre-boot). */
export function _getAuth(): AuthManager | undefined {
	return _instance;
}

const auth: AuthManager = new Proxy({} as AuthManager, {
	get(_target, prop) {
		if (!_instance) {
			throw new Error(
				"[warden] AuthManager singleton accessed before WardenProvider.boot() ran. " +
					"Check that `@c9up/warden/provider` is listed in your reamrc.ts providers.",
			);
		}
		const value = Reflect.get(_instance, prop, _instance);
		return typeof value === "function" ? value.bind(_instance) : value;
	},
});

export default auth;
