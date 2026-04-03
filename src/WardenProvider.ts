import type { AppContext } from '@c9up/ream'
import { AuthManager } from './AuthManager.js'
import { JwtStrategy } from './strategies/JwtStrategy.js'
import type { JwtStrategyConfig } from './strategies/JwtStrategy.js'

export default class WardenProvider {
  constructor(protected app: AppContext) {}

  register() {
    this.app.container.singleton(AuthManager, () => {
      const config = this.app.config.get<{
        defaultStrategy?: string
        jwt?: JwtStrategyConfig
      }>('auth')

      const strategies: Record<string, JwtStrategy> = {}

      if (config?.jwt) {
        const jwt = new JwtStrategy(config.jwt)
        strategies.jwt = jwt
        this.app.container.singleton(JwtStrategy, () => jwt)
      }

      return new AuthManager({
        defaultStrategy: config?.defaultStrategy ?? 'jwt',
        strategies,
      })
    })
  }

  async boot() {}
  async start() {}
  async ready() {}
  async shutdown() {}
}
