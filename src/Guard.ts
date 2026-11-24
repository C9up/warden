/**
 * @Guard() decorator — protects route handlers with authentication.
 *
 * @implements FR50, FR51
 */

// Side-effect import: registers the `Reflect.defineMetadata` / `getMetadata`
// methods used below. Pulled in here (not transitively via the framework)
// so warden remains self-sufficient when published / consumed standalone.
import "reflect-metadata";
import { E_WARDEN_EMPTY_GATE_REQUIREMENT } from "./errors.js";

/** Guard decorator metadata key — Symbol.for ensures cross-module accessibility. */
const GUARD_KEY = Symbol.for("warden:guard");
const PERMISSION_KEY = Symbol.for("warden:permission");
const ROLE_KEY = Symbol.for("warden:role");
const MFA_KEY = Symbol.for("warden:mfa");

/** `Controller.action`, for a message: the target is a prototype or a class. */
function actionName(target: object, propertyKey: string | symbol): string {
	const owner: unknown =
		typeof target === "function" ? target : Reflect.get(target, "constructor");
	const name =
		typeof owner === "function" && owner.name !== ""
			? owner.name
			: "controller";
	return `${name}.${String(propertyKey)}`;
}

/**
 * The names a list-valued decorator requires, or the refusal of a list that
 * names none. An empty requirement — `@Role(...rolesFromConfig)` with an
 * empty list — would read as "no requirement" and leave the action open to
 * every request, so it is refused where it is declared: when the class loads.
 */
function requirementList(
	value: unknown,
	target: object,
	propertyKey: string | symbol,
	decorator: string,
): string[] {
	const names = Array.isArray(value)
		? value.filter((item): item is string => typeof item === "string")
		: [];
	if (names.length === 0 || !names.some((name) => name.length > 0)) {
		throw new E_WARDEN_EMPTY_GATE_REQUIREMENT([
			actionName(target, propertyKey),
			decorator,
		]);
	}
	return names;
}

/**
 * @Guard('jwt') — require authentication via the named strategy.
 * At least one strategy name is required.
 */
export function Guard(first: string, ...rest: string[]): MethodDecorator {
	const strategies = [first, ...rest];
	return (target, propertyKey) => {
		Reflect.defineMetadata(
			GUARD_KEY,
			requirementList(strategies, target, propertyKey, "@Guard()"),
			target,
			propertyKey,
		);
	};
}

/**
 * @Permission('orders.create') — require specific permissions. At least one
 * is required.
 */
export function Permission(...permissions: string[]): MethodDecorator {
	return (target, propertyKey) => {
		Reflect.defineMetadata(
			PERMISSION_KEY,
			requirementList(permissions, target, propertyKey, "@Permission()"),
			target,
			propertyKey,
		);
	};
}

/**
 * @Role('admin') — require specific roles. At least one is required.
 */
export function Role(...roles: string[]): MethodDecorator {
	return (target, propertyKey) => {
		Reflect.defineMetadata(
			ROLE_KEY,
			requirementList(roles, target, propertyKey, "@Role()"),
			target,
			propertyKey,
		);
	};
}

/*
 * The readers below walk the prototype chain (`Reflect.getMetadata`), so an
 * action a controller inherits keeps the guard and the authorization its parent
 * declared: `class UsersController extends AdminController {}` routes
 * `[UsersController, 'index']` to a method declared on `AdminController`, and
 * reading only the subclass's own metadata made that route public.
 *
 * The metadata belongs to the action NAME, not to the function: an override
 * that declares nothing inherits its parent's decorators too, so redefining a
 * method can never drop a guard by accident. An override that declares its own
 * decorator replaces the parent's for that decorator.
 *
 * Absent metadata is no requirement (`[]`). Metadata that is present and names
 * nothing — written by hand, or by another tool, past the decorators' check —
 * throws `E_WARDEN_EMPTY_GATE_REQUIREMENT`: read as "no requirement" it would
 * make the action public, so the request fails closed instead.
 */

/** The list stored under `key`: `[]` when absent, refused when it names nothing. */
function readRequirement(
	key: symbol,
	target: object,
	propertyKey: string | symbol,
	decorator: string,
): string[] {
	const value: unknown = Reflect.getMetadata(key, target, propertyKey);
	if (value === undefined) return [];
	return requirementList(value, target, propertyKey, decorator);
}

/** Get guard metadata. */
export function getGuardMetadata(
	target: object,
	propertyKey: string | symbol,
): string[] {
	return readRequirement(GUARD_KEY, target, propertyKey, "@Guard()");
}

/** Get permission metadata. */
export function getPermissionMetadata(
	target: object,
	propertyKey: string | symbol,
): string[] {
	return readRequirement(PERMISSION_KEY, target, propertyKey, "@Permission()");
}

/** Get role metadata. */
export function getRoleMetadata(
	target: object,
	propertyKey: string | symbol,
): string[] {
	return readRequirement(ROLE_KEY, target, propertyKey, "@Role()");
}

/**
 * @RequireMfa() — require the authenticated user to have completed multi-factor
 * authentication. The auth middleware rejects with 403 `MFA_REQUIRED` when the
 * user payload lacks a truthy `mfa` claim (set by your MFA step-up flow once
 * `MfaManager.verify()` succeeds).
 */
export function RequireMfa(): MethodDecorator {
	return (target, propertyKey) => {
		Reflect.defineMetadata(MFA_KEY, true, target, propertyKey);
	};
}

/** Whether the route requires completed MFA. */
export function getRequireMfaMetadata(
	target: object,
	propertyKey: string | symbol,
): boolean {
	return Reflect.getMetadata(MFA_KEY, target, propertyKey) ?? false;
}
