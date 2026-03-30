/**
 * @Guard() decorator — protects route handlers with authentication.
 *
 * @implements FR50, FR51
 */

/** Guard decorator metadata key — Symbol.for ensures cross-module accessibility. */
const GUARD_KEY = Symbol.for('warden:guard')
const PERMISSION_KEY = Symbol.for('warden:permission')
const ROLE_KEY = Symbol.for('warden:role')

/**
 * @Guard('jwt') — require authentication via the named strategy.
 * At least one strategy name is required.
 */
export function Guard(first: string, ...rest: string[]): MethodDecorator {
  const strategies = [first, ...rest]
  return (target, propertyKey) => {
    Reflect.defineMetadata(GUARD_KEY, strategies, target, propertyKey)
  }
}

/**
 * @Permission('orders.create') — require specific permissions.
 */
export function Permission(...permissions: string[]): MethodDecorator {
  return (target, propertyKey) => {
    Reflect.defineMetadata(PERMISSION_KEY, permissions, target, propertyKey)
  }
}

/**
 * @Role('admin') — require specific roles.
 */
export function Role(...roles: string[]): MethodDecorator {
  return (target, propertyKey) => {
    Reflect.defineMetadata(ROLE_KEY, roles, target, propertyKey)
  }
}

/** Get guard metadata. */
export function getGuardMetadata(target: object, propertyKey: string | symbol): string[] {
  return Reflect.getOwnMetadata(GUARD_KEY, target, propertyKey) ?? []
}

/** Get permission metadata. */
export function getPermissionMetadata(target: object, propertyKey: string | symbol): string[] {
  return Reflect.getOwnMetadata(PERMISSION_KEY, target, propertyKey) ?? []
}

/** Get role metadata. */
export function getRoleMetadata(target: object, propertyKey: string | symbol): string[] {
  return Reflect.getOwnMetadata(ROLE_KEY, target, propertyKey) ?? []
}
