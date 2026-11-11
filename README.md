# @c9up/warden

Authentication & authorization for Node.js. Multi-strategy auth, RBAC, decorators.

## Usage

```typescript
import { AuthManager, Guard, Permission, Role } from '@c9up/warden'

const auth = new AuthManager({
  defaultStrategy: 'jwt',
  strategies: { jwt: myJwtStrategy },
})

const result = await auth.authenticate({ email: 'admin@c9up.com', password: 'secret' })
if (result.authenticated && result.user) {
  await auth.hasRole(result.user, 'admin') // true
}

class OrderController {
  @Guard('jwt')
  @Permission('orders.create')
  async create() { /* protected */ }
}
```

Authorization decorators imply authentication: an action carrying `@Role`,
`@Permission` or `@RequireMfa` without `@Guard` is authenticated with the default
guard (an anonymous request gets a 401). Decorators are read through the
prototype chain, so an action a controller inherits keeps its parent's guard and
authorization; an override inherits them too unless it declares its own.

## Features

- Multi-strategy AuthManager (JWT, session, access tokens, HTTP Basic)
- `@Guard()`, `@Permission()`, `@Role()` decorators
- RBAC: `hasRole`, `hasPermission`, `hasAllPermissions`
- Unified authorization: abilities & policies (`Bouncer`) over one resolver — RBAC + ACL + ownership + multi-tenant scope, zero dependency
- Strategy exception safety (catch → AuthResult)
- Runtime strategy registration
- **Multi-factor authentication** — TOTP, backup codes, email/SMS OTP, WebAuthn/passkeys, all dependency-free
- JWT and session revocation blacklist (Memory / Redis-KeyDB / resilient fallback drivers)

## Access tokens

Opaque bearer tokens for APIs, CLIs and mobile apps. A token value looks like
`oat_<identifier>.<secret>`; only `sha256(secret)` is stored, the comparison is
constant-time, and the secret ends with a CRC-32 checksum so secret scanners can
recognise a leaked token.

```typescript
import { AccessTokensProvider, MemoryAccessTokenStore } from '@c9up/warden'
import { apiKeyGuard, defineConfig } from '@c9up/warden/config'

// Implement AccessTokenStore over your own table in production.
const tokens = new AccessTokensProvider({ store: new MemoryAccessTokenStore(), expiresIn: '30 days' })

export default defineConfig({
  default: 'api',
  guards: { api: apiKeyGuard({ tokens, findUser: (id) => User.find(id) }) },
})

// Mint — `value` is readable only on the token just created.
const token = await tokens.create(user, ['orders:read'], { name: 'CI' })
token.value.release() // "oat_…" — hand it to the client now

// In a handler, after the guard authenticated the request:
ctx.auth.user.currentAccessToken.authorize('orders:read')
```

The guard reads `Authorization: Bearer <token>` or the `x-api-key` header
(`headerName` to change it), reloads the user through `findUser` on every
request, and attaches the token as `user.currentAccessToken` (`abilities`,
`allows`, `denies`, `authorize`, `isExpired`, `lastUsedAt`). A token's abilities
are never merged into `user.permissions`, which holds the user's own permissions:
what a request may do is what the user may do AND what the token allows.
`@Permission(...)`, `hasPermission` and `hasAllPermissions` enforce exactly that
for a request made with a token (`tokenAllows(user, permission)` is the check on
its own); a session or JWT user is checked against their own permissions only.

`tokens.all(user)`, `find`, `delete`, `deleteAll` manage a user's tokens;
`tokens.invalidate(value)` (or `guard.invalidateToken(value)`) revokes the token
behind a presented value.

## Sessions and remember-me

`ctx.auth.use('web').logout()` ends the session and the remember-me credential:
the cookie is cleared and the stored token behind it deleted.

Revocation lists (`TokenBlacklist`) can sit on a `ResilientBlacklistDriver`,
which keeps a local record beside Redis/KeyDB. When the primary is unreachable
and the local record does not know a credential, the check fails (the request is
refused as a server error, never treated as "not revoked"). Pass
`{ failOpen: true }` to let such credentials through instead, for a deployment
whose only consumer is a short-lived JWT.

`AuthRateLimiter` and the MFA lockout count attempts in a `MemoryAttemptStore`
by default: per process, bounded, and never dropping a live counter to make room
(a new key is refused while the store is full). In production, use
`RedisAttemptStore`: it is shared by every instance and has no such bound.

## Multi-factor authentication

Four providers, all implemented on `node:crypto` with **zero third-party dependency**
(WebAuthn included). Every provider and the manager take pluggable stores, defaulting
to in-memory — supply persistent stores (Atlas, KeyDB…) in production.

```typescript
import {
  MfaManager,
  TotpProvider,
  BackupCodesProvider,
  RequireMfa,
} from '@c9up/warden'

const mfa = new MfaManager({
  issuer: 'Fluveo',
  totp: new TotpProvider(),
  backupCodes: new BackupCodesProvider(),
  // store: new AtlasMfaFactorStore(db),   // persistent factors in production
  rateLimit: { maxAttempts: 5, windowSeconds: 900 }, // per-user brute-force lock
})

// Enroll (returns the otpauth:// URI to render as a QR code)
const { factorId, uri } = await mfa.enrollTotp({ id: user.id, name: user.email })
await mfa.confirmTotp(user.id, factorId, codeFromAuthenticatorApp)   // → true once confirmed
const recoveryCodes = await mfa.createBackupCodes(user.id)  // show once

// Factor operations name the owner, and refuse a factor that is not theirs.
await mfa.disableFactor(user.id, factorId)                  // → false if not theirs

// At sign-in step-up: TOTP code OR a backup code (rate-limited)
if (await mfa.verify(user.id, submittedCode)) {
  const token = auth.issueFor(user, 'jwt', { mfa: true })  // JWT: the token carries the step-up
  // or, on a session guard: ctx.auth.use('web').markMfaVerified()
}
```

Gate sensitive routes — the middleware returns `403 E_WARDEN_MFA_REQUIRED` unless
the request's credential completed the step-up (a JWT signed with `{ mfa: true }`,
or a session marked with `markMfaVerified()`):

```typescript
class TransferController {
  @Guard('jwt')
  @RequireMfa()
  async transfer() { /* only reachable after MFA step-up */ }
}
```

Wire the manager into the container via config:

```typescript
// config/auth.ts
import { defineConfig } from '@c9up/warden/config'
export default defineConfig({ jwt: { /* … */ }, mfa: { manager: mfa } })
```

Email/SMS OTP (`OtpProvider`) and WebAuthn/passkeys (`WebauthnProvider`) are used
directly — OTP needs a delivery channel, WebAuthn persists passkeys in its own store.

## License

MIT
