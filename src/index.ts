/**
 * @module @c9up/warden
 * @description Warden — Authentication & authorization for the Ream framework
 * @implements FR48, FR49, FR50, FR51, FR52, FR53
 */

export { AuthManager } from './AuthManager.js'
export type { AuthConfig, AuthResult, AuthStrategy, UserPayload } from './AuthManager.js'
export { Guard, Permission, Role, getGuardMetadata, getPermissionMetadata, getRoleMetadata } from './Guard.js'
export { JwtStrategy, generateJwtSecret } from './strategies/JwtStrategy.js'
export type { JwtStrategyConfig } from './strategies/JwtStrategy.js'
export { WardenError } from './errors.js'
