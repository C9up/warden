/**
 * FirstContactManager — OAuth2 social authentication.
 *
 * Usage:
 *   firstContact.use('google').redirectUrl()
 *   firstContact.use('google').callback(code)
 */

import type { FirstContactDriver, OAuthToken, OAuthUser } from "./types.js";

export class FirstContactManager {
	#drivers: Map<string, FirstContactDriver> = new Map();

	use(name: string): FirstContactDriver {
		const driver = this.#drivers.get(name);
		if (!driver)
			throw new Error(
				`OAuth driver '${name}' not registered. Available: ${[...this.#drivers.keys()].join(", ")}`,
			);
		return driver;
	}

	register(name: string, driver: FirstContactDriver): void {
		this.#drivers.set(name, driver);
	}

	redirect(name: string, state?: string): string {
		return this.use(name).redirectUrl(state);
	}

	/**
	 * Handle the OAuth callback. Pass `state` (from the query string) and
	 * `expectedState` (from the session, stored at redirect time) for CSRF
	 * protection. Omitting `expectedState` logs a security warning.
	 */
	async callback(
		name: string,
		code: string,
		state?: string,
		expectedState?: string,
	): Promise<{ user: OAuthUser; token: OAuthToken }> {
		if (!expectedState) {
			throw new Error(
				`[warden] OAuth callback for '${name}' requires expectedState for CSRF protection. ` +
					`Store the state from redirect() in the session and pass it here.`,
			);
		}
		return this.use(name).callback(code, state, expectedState);
	}

	get registeredDrivers(): string[] {
		return [...this.#drivers.keys()];
	}
}
