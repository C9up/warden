import 'reflect-metadata'
import { describe, expect, it } from 'vitest'
import { AuthManager, Guard, Permission, Role, getGuardMetadata, getPermissionMetadata, getRoleMetadata } from '../../src/index.js'
import type { AuthResult, AuthStrategy, UserPayload } from '../../src/index.js'

// === Mock strategies ===

const mockJwtStrategy: AuthStrategy = {
  name: 'jwt',
  async authenticate(creds) {
    if (creds.email === 'admin@c9up.com' && creds.password === 'secret') {
      return { authenticated: true, user: { id: '1', roles: ['admin'], permissions: ['orders.create', 'orders.read'] } }
    }
    return { authenticated: false, error: 'Invalid credentials' }
  },
  async verify(token) {
    if (token === 'valid-jwt-token') {
      return { authenticated: true, user: { id: '1', roles: ['admin'] } }
    }
    return { authenticated: false, error: 'Invalid token' }
  },
}

const mockSessionStrategy: AuthStrategy = {
  name: 'session',
  async authenticate() { return { authenticated: true, user: { id: '2' } } },
  async verify(token) { return token === 'session-id' ? { authenticated: true, user: { id: '2' } } : { authenticated: false, error: 'Invalid session' } },
}

const throwingStrategy: AuthStrategy = {
  name: 'throwing',
  async authenticate() { throw new Error('Network timeout') },
  async verify() { throw new Error('Connection refused') },
}

describe('warden > AuthManager', () => {
  it('authenticates with default strategy', async () => {
    const auth = new AuthManager({ defaultStrategy: 'jwt', strategies: { jwt: mockJwtStrategy } })
    const result = await auth.authenticate({ email: 'admin@c9up.com', password: 'secret' })
    expect(result.authenticated).toBe(true)
    expect(result.user?.id).toBe('1')
  })

  it('rejects invalid credentials', async () => {
    const auth = new AuthManager({ defaultStrategy: 'jwt', strategies: { jwt: mockJwtStrategy } })
    const result = await auth.authenticate({ email: 'wrong', password: 'wrong' })
    expect(result.authenticated).toBe(false)
    expect(result.error).toBe('Invalid credentials')
  })

  it('verifies token', async () => {
    const auth = new AuthManager({ defaultStrategy: 'jwt', strategies: { jwt: mockJwtStrategy } })
    expect((await auth.verify('valid-jwt-token')).authenticated).toBe(true)
    expect((await auth.verify('invalid')).authenticated).toBe(false)
  })

  it('uses named strategy', async () => {
    const auth = new AuthManager({
      defaultStrategy: 'jwt',
      strategies: { jwt: mockJwtStrategy, session: mockSessionStrategy },
    })
    const result = await auth.verify('session-id', 'session')
    expect(result.authenticated).toBe(true)
    expect(result.user?.id).toBe('2')
  })

  it('throws on unknown strategy', () => {
    const auth = new AuthManager({ defaultStrategy: 'jwt', strategies: {} })
    expect(() => auth.getStrategy()).toThrow('Auth strategy')
  })

  it('catches strategy exceptions on authenticate', async () => {
    const auth = new AuthManager({ defaultStrategy: 'throwing', strategies: { throwing: throwingStrategy } })
    const result = await auth.authenticate({ email: 'test' })
    expect(result.authenticated).toBe(false)
    expect(result.error).toBe('Network timeout')
  })

  it('catches strategy exceptions on verify', async () => {
    const auth = new AuthManager({ defaultStrategy: 'throwing', strategies: { throwing: throwingStrategy } })
    const result = await auth.verify('some-token')
    expect(result.authenticated).toBe(false)
    expect(result.error).toBe('Connection refused')
  })
})

describe('warden > RBAC', () => {
  const user: UserPayload = { id: '1', roles: ['admin', 'editor'], permissions: ['orders.create', 'orders.read', 'users.list'] }

  it('checks role', () => {
    const auth = new AuthManager({ defaultStrategy: 'jwt', strategies: { jwt: mockJwtStrategy } })
    expect(auth.hasRole(user, 'admin')).toBe(true)
    expect(auth.hasRole(user, 'superadmin')).toBe(false)
  })

  it('checks permission', () => {
    const auth = new AuthManager({ defaultStrategy: 'jwt', strategies: { jwt: mockJwtStrategy } })
    expect(auth.hasPermission(user, 'orders.create')).toBe(true)
    expect(auth.hasPermission(user, 'orders.delete')).toBe(false)
  })

  it('checks all permissions', () => {
    const auth = new AuthManager({ defaultStrategy: 'jwt', strategies: { jwt: mockJwtStrategy } })
    expect(auth.hasAllPermissions(user, ['orders.create', 'orders.read'])).toBe(true)
    expect(auth.hasAllPermissions(user, ['orders.create', 'orders.delete'])).toBe(false)
  })

  it('hasAllPermissions returns false for empty array', () => {
    const auth = new AuthManager({ defaultStrategy: 'jwt', strategies: { jwt: mockJwtStrategy } })
    expect(auth.hasAllPermissions(user, [])).toBe(false)
  })
})

describe('warden > decorators', () => {
  class TestController {
    @Guard('jwt')
    @Permission('orders.create')
    @Role('admin')
    async createOrder() {}

    @Guard('jwt', 'session')
    async multiGuard() {}
  }

  it('@Guard stores strategy names via Symbol.for', () => {
    const guards = getGuardMetadata(TestController.prototype, 'createOrder')
    expect(guards).toEqual(['jwt'])
  })

  it('@Guard supports multiple strategies', () => {
    const guards = getGuardMetadata(TestController.prototype, 'multiGuard')
    expect(guards).toEqual(['jwt', 'session'])
  })

  it('@Permission stores permissions', () => {
    const perms = getPermissionMetadata(TestController.prototype, 'createOrder')
    expect(perms).toEqual(['orders.create'])
  })

  it('@Role stores roles', () => {
    const roles = getRoleMetadata(TestController.prototype, 'createOrder')
    expect(roles).toEqual(['admin'])
  })

  it('metadata is accessible via Symbol.for directly', () => {
    const guards = Reflect.getOwnMetadata(Symbol.for('warden:guard'), TestController.prototype, 'createOrder')
    expect(guards).toEqual(['jwt'])
  })
})
