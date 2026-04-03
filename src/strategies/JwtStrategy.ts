/**
 * JwtStrategy — HMAC-SHA256 JWT authentication strategy.
 *
 * Pure TypeScript fallback implementation. When the ream-security NAPI binary
 * is available, jwt_sign/jwt_verify from Rust can be used instead for
 * higher throughput.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { AuthStrategy, AuthResult, UserPayload } from '../AuthManager.js'

const ALGORITHM = 'sha256'

interface JwtPayloadData {
  sub: string
  roles?: string[]
  permissions?: string[]
  iat: number
  exp: number
  [key: string]: unknown
}

function base64UrlEncode(data: string): string {
  return Buffer.from(data).toString('base64url')
}

function base64UrlDecode(encoded: string): string {
  return Buffer.from(encoded, 'base64url').toString('utf8')
}

function sign(payload: JwtPayloadData, secret: string): string {
  const header = { alg: 'HS256', typ: 'JWT' }
  const headerB64 = base64UrlEncode(JSON.stringify(header))
  const payloadB64 = base64UrlEncode(JSON.stringify(payload))
  const signature = createHmac(ALGORITHM, secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url')
  return `${headerB64}.${payloadB64}.${signature}`
}

function verify(token: string, secret: string): JwtPayloadData | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null

  const [headerB64, payloadB64, signatureB64] = parts
  const expectedSig = createHmac(ALGORITHM, secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url')

  const sigBuf = Buffer.from(signatureB64, 'base64url')
  const expectedBuf = Buffer.from(expectedSig, 'base64url')
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
    return null
  }

  const payload = JSON.parse(base64UrlDecode(payloadB64)) as JwtPayloadData
  const now = Math.floor(Date.now() / 1000)
  if (payload.exp && payload.exp < now) return null

  return payload
}

export interface JwtStrategyConfig {
  secret: string
  expiresInSeconds?: number
  findUser: (id: string) => Promise<UserPayload | null>
  verifyCredentials: (email: string, password: string) => Promise<UserPayload | null>
}

export class JwtStrategy implements AuthStrategy {
  name = 'jwt'
  private secret: string
  private expiresIn: number
  private findUser: JwtStrategyConfig['findUser']
  private verifyCredentials: JwtStrategyConfig['verifyCredentials']

  constructor(config: JwtStrategyConfig) {
    if (config.secret.length < 32) {
      throw new Error('JWT secret must be at least 32 characters')
    }
    this.secret = config.secret
    this.expiresIn = config.expiresInSeconds ?? 3600
    this.findUser = config.findUser
    this.verifyCredentials = config.verifyCredentials
  }

  async authenticate(credentials: Record<string, unknown>): Promise<AuthResult> {
    const email = credentials.email as string
    const password = credentials.password as string
    if (!email || !password) {
      return { authenticated: false, error: 'Email and password are required' }
    }

    const user = await this.verifyCredentials(email, password)
    if (!user) {
      return { authenticated: false, error: 'Invalid credentials' }
    }

    const now = Math.floor(Date.now() / 1000)
    const token = sign({
      sub: user.id, roles: user.roles, permissions: user.permissions,
      iat: now, exp: now + this.expiresIn,
    }, this.secret)

    return { authenticated: true, user: { ...user, token } }
  }

  async verify(token: string): Promise<AuthResult> {
    const payload = verify(token, this.secret)
    if (!payload) {
      return { authenticated: false, error: 'Invalid or expired token' }
    }

    const user = await this.findUser(payload.sub)
    if (!user) {
      return { authenticated: false, error: 'User not found' }
    }

    return { authenticated: true, user }
  }

  signToken(user: UserPayload): string {
    const now = Math.floor(Date.now() / 1000)
    return sign({
      sub: user.id, roles: user.roles, permissions: user.permissions,
      iat: now, exp: now + this.expiresIn,
    }, this.secret)
  }
}

export function generateJwtSecret(): string {
  return randomBytes(48).toString('base64url')
}
