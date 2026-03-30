/**
 * AuthManager — manages multiple authentication strategies.
 *
 * @implements FR48, FR50, FR51
 */

import { WardenError } from './errors.js'

export interface UserPayload {
  id: string
  roles?: string[]
  permissions?: string[]
  [key: string]: unknown
}

export interface AuthResult {
  authenticated: boolean
  user?: UserPayload
  error?: string
}

export interface AuthStrategy {
  name: string
  authenticate(credentials: Record<string, unknown>): Promise<AuthResult>
  verify(token: string): Promise<AuthResult>
}

export interface AuthConfig {
  defaultStrategy: string
  strategies: Record<string, AuthStrategy>
}

/**
 * Manages authentication strategies and provides guard/permission checks.
 */
export class AuthManager {
  private strategies: Map<string, AuthStrategy> = new Map()
  private defaultStrategy: string

  constructor(config: AuthConfig) {
    this.defaultStrategy = config.defaultStrategy
    for (const [name, strategy] of Object.entries(config.strategies)) {
      this.strategies.set(name, strategy)
    }
    // Validate defaultStrategy exists (if strategies were provided)
    if (Object.keys(config.strategies).length > 0 && !this.strategies.has(config.defaultStrategy)) {
      throw new WardenError('INVALID_CONFIG', `defaultStrategy '${config.defaultStrategy}' is not present in strategies`)
    }
  }

  /** Authenticate with credentials using a specific or default strategy. */
  async authenticate(
    credentials: Record<string, unknown>,
    strategyName?: string,
  ): Promise<AuthResult> {
    const strategy = this.getStrategy(strategyName)
    try {
      return await strategy.authenticate(credentials)
    } catch (err) {
      return { authenticated: false, error: err instanceof Error ? err.message : 'Unknown authentication error' }
    }
  }

  /** Verify a token (JWT, session, API key). */
  async verify(token: string, strategyName?: string): Promise<AuthResult> {
    const strategy = this.getStrategy(strategyName)
    try {
      return await strategy.verify(token)
    } catch (err) {
      return { authenticated: false, error: err instanceof Error ? err.message : 'Unknown verification error' }
    }
  }

  /** Check if a user has a specific role. */
  hasRole(user: UserPayload, role: string): boolean {
    return user.roles?.includes(role) ?? false
  }

  /** Check if a user has a specific permission. */
  hasPermission(user: UserPayload, permission: string): boolean {
    return user.permissions?.includes(permission) ?? false
  }

  /** Check if a user has ALL required permissions. */
  hasAllPermissions(user: UserPayload, permissions: string[]): boolean {
    if (permissions.length === 0) return false
    return permissions.every((p) => this.hasPermission(user, p))
  }

  /** Get a registered strategy by name. */
  getStrategy(name?: string): AuthStrategy {
    const strategyName = name ?? this.defaultStrategy
    const strategy = this.strategies.get(strategyName)
    if (!strategy) {
      throw new WardenError('STRATEGY_NOT_FOUND', `Auth strategy '${strategyName}' not registered`, {
        hint: 'Call registerStrategy() before using this strategy name.',
      })
    }
    return strategy
  }

  /** Register a new strategy at runtime. */
  registerStrategy(name: string, strategy: AuthStrategy): void {
    this.strategies.set(name, strategy)
  }

  /** Get all registered strategy names. */
  getStrategyNames(): string[] {
    return [...this.strategies.keys()]
  }
}
