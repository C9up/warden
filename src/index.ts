/**
 * @module @c9up/warden
 * @description Warden — Authentication for the Ream framework
 * @implements FR48, FR49, FR50, FR51, FR52, FR53
 */

export { AuthManager } from './AuthManager.js'
export type { AuthConfig, AuthStrategy, AuthResult, UserPayload } from './AuthManager.js'
export { Guard, Permission, Role, getGuardMetadata, getPermissionMetadata, getRoleMetadata } from './Guard.js'
