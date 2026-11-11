/**
 * Strip the prototype-pollution keys from a user payload.
 *
 * Lives in its own module so `AuthManager` and `Authenticator` do not have to
 * import each other's values: the manager builds an authenticator, and the
 * authenticator sanitises — putting both in one file made a runtime cycle.
 */

import type { UserPayload } from "./AuthManager.js";

export function sanitizePayload(user: UserPayload): void {
	for (const key of ["__proto__", "constructor", "prototype"]) {
		// Own keys only: `constructor` is always reachable through the
		// prototype, and deleting an inherited name is a no-op anyway.
		if (Object.hasOwn(user, key)) {
			delete user[key];
		}
	}
}
