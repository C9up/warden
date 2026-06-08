/**
 * Bouncer policy decorators — `@allowGuest()` / `@action()` mark policy methods
 * that a guest (null user) may reach. Mirrors the `Guard.ts` idiom (D9):
 * `reflect-metadata` side-effect import, a `Symbol.for` key, the legacy
 * `MethodDecorator` signature, and a `getActionMetadata` reader.
 */

// Side-effect import: registers `Reflect.defineMetadata` / `getMetadata`. Pulled
// in here (not transitively) so warden stays self-sufficient when published.
import "reflect-metadata";
import type { AbilityOptions } from "./types.js";

/** Action metadata key — Symbol.for ensures cross-module accessibility. */
const ACTION_KEY = Symbol.for("warden:bouncer:action");

/**
 * `@action({ allowGuest })` — configure a policy method's evaluation options.
 */
export function action(options: AbilityOptions): MethodDecorator {
	return (target, propertyKey) => {
		Reflect.defineMetadata(ACTION_KEY, options, target, propertyKey);
	};
}

/**
 * `@allowGuest()` — let a guest (null user) reach this policy method.
 * Equivalent to `@action({ allowGuest: true })`.
 */
export function allowGuest(): MethodDecorator {
	return action({ allowGuest: true });
}

/**
 * Read a policy method's action metadata. Walks the prototype chain
 * (`Reflect.getMetadata`) so it resolves from a policy INSTANCE — legacy
 * decorators write metadata onto the class prototype, where the instance
 * inherits it. Absent ⇒ `{}` (⇒ `allowGuest` falsy ⇒ guest denied).
 */
export function getActionMetadata(
	target: object,
	propertyKey: string | symbol,
): AbilityOptions {
	return Reflect.getMetadata(ACTION_KEY, target, propertyKey) ?? {};
}
