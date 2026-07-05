/**
 * AbilitiesBuilder — a chainable builder that fluently assembles an object of
 * named abilities (Adonis `AbilitiesBuilder`). Each `.define(...)` delegates to
 * `Bouncer.ability` and stores the result on `.abilities`, returning `this` so
 * calls chain: `new AbilitiesBuilder().define(a).define(b).abilities`.
 */

import type { UserPayload } from "../AuthManager.js";
import { Bouncer } from "./Bouncer.js";
import type { Ability, AbilityOptions, AuthorizerResponse } from "./types.js";

export class AbilitiesBuilder {
	/** The abilities accumulated so far, keyed by name. */
	readonly abilities: Record<string, Ability<never[]>>;

	constructor(abilities: Record<string, Ability<never[]>> = {}) {
		this.abilities = abilities;
	}

	/**
	 * Define a named ability (Adonis `.define(name, authorizer, options?)`). The
	 * callback receives a non-null user (a guest is denied by the evaluator before
	 * it runs); pass `{ allowGuest: true }` to let the callback run for a guest.
	 */
	define<Args extends unknown[]>(
		name: string,
		authorizer: (user: UserPayload, ...args: Args) => AuthorizerResponse,
		options?: AbilityOptions,
	): this {
		// Delegate the callback wrapping to `Bouncer.ability` (guest-denied form),
		// then apply the `allowGuest` option. Store without the `__args` phantom —
		// its concrete-args brand cannot widen to the `never[]` storage slot, while
		// `execute` is already non-generic.
		const built = Bouncer.ability(authorizer);
		this.abilities[name] = {
			allowGuest: options?.allowGuest ?? built.allowGuest,
			execute: built.execute,
		};
		return this;
	}
}
