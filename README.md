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
auth.hasRole(result.user!, 'admin') // true

class OrderController {
  @Guard('jwt')
  @Permission('orders.create')
  async create() { /* protected */ }
}
```

## Features

- Multi-strategy AuthManager (JWT, session, API key, OAuth)
- `@Guard()`, `@Permission()`, `@Role()` decorators
- RBAC: `hasRole`, `hasPermission`, `hasAllPermissions`
- Unified authorization: Bouncer-shaped abilities & policies over one resolver — RBAC + ACL + ownership + multi-tenant scope, zero `@adonisjs/bouncer` dependency
- Strategy exception safety (catch → AuthResult)
- Runtime strategy registration
- **Multi-factor authentication** — TOTP, backup codes, email/SMS OTP, WebAuthn/passkeys, all dependency-free
- JWT revocation blacklist (Memory / Redis-KeyDB / resilient fallback drivers)

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
await mfa.confirmTotp(factorId, codeFromAuthenticatorApp)   // → true once confirmed
const recoveryCodes = await mfa.createBackupCodes(user.id)  // show once

// At sign-in step-up: TOTP code OR a backup code (rate-limited)
if (await mfa.verify(user.id, submittedCode)) {
  // issue a JWT carrying `mfa: true`
}
```

Gate sensitive routes — the middleware returns `403 MFA_REQUIRED` unless the
authenticated user's payload carries a truthy `mfa` claim:

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
