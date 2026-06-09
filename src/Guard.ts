/**
 * @Guard() decorator — protects route handlers with authentication.
 *
 * @implements FR50, FR51
 */

// Side-effect import: registers the `Reflect.defineMetadata` / `getOwnMetadata`
// methods used below. Pulled in here (not transitively via the framework)
// so warden remains self-sufficient when published / consumed standalone.
import "reflect-metadata";

/** Guard decorator metadata key — Symbol.for ensures cross-module accessibility. */
const GUARD_KEY = Symbol.for("warden:guard");
const PERMISSION_KEY = Symbol.for("warden:permission");
const ROLE_KEY = Symbol.for("warden:role");
const MFA_KEY = Symbol.for("warden:mfa");

/**
 * @Guard('jwt') — require authentication via the named strategy.
 * At least one strategy name is required.
 */
export function Guard(first: string, ...rest: string[]): MethodDecorator {
	const strategies = [first, ...rest];
	return (target, propertyKey) => {
		Reflect.defineMetadata(GUARD_KEY, strategies, target, propertyKey);
	};
}

/**
 * @Permission('orders.create') — require specific permissions.
 */
export function Permission(...permissions: string[]): MethodDecorator {
	return (target, propertyKey) => {
		Reflect.defineMetadata(PERMISSION_KEY, permissions, target, propertyKey);
	};
}

/**
 * @Role('admin') — require specific roles.
 */
export function Role(...roles: string[]): MethodDecorator {
	return (target, propertyKey) => {
		Reflect.defineMetadata(ROLE_KEY, roles, target, propertyKey);
	};
}

/** Get guard metadata. */
export function getGuardMetadata(
	target: object,
	propertyKey: string | symbol,
): string[] {
	return Reflect.getOwnMetadata(GUARD_KEY, target, propertyKey) ?? [];
}

/** Get permission metadata. */
export function getPermissionMetadata(
	target: object,
	propertyKey: string | symbol,
): string[] {
	return Reflect.getOwnMetadata(PERMISSION_KEY, target, propertyKey) ?? [];
}

/** Get role metadata. */
export function getRoleMetadata(
	target: object,
	propertyKey: string | symbol,
): string[] {
	return Reflect.getOwnMetadata(ROLE_KEY, target, propertyKey) ?? [];
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
	return Reflect.getOwnMetadata(MFA_KEY, target, propertyKey) ?? false;
}
