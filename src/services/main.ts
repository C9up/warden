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

let instance: AuthManager | undefined;

/** @internal Bind the singleton (called by WardenProvider). */
export function setAuth(value: AuthManager): void {
	instance = value;
}

/** @internal Read the singleton (or `undefined` pre-boot). */
export function getAuth(): AuthManager | undefined {
	return instance;
}

const auth: AuthManager = new Proxy({} as AuthManager, {
	get(_target, prop) {
		if (!instance) {
			throw new Error(
				"[warden] AuthManager singleton accessed before WardenProvider.boot() ran. " +
					"Check that `@c9up/warden/provider` is listed in your reamrc.ts providers.",
			);
		}
		const value = Reflect.get(instance, prop, instance);
		return typeof value === "function" ? value.bind(instance) : value;
	},
});

export default auth;
