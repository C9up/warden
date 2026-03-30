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
- Strategy exception safety (catch → AuthResult)
- Runtime strategy registration

## License

MIT
