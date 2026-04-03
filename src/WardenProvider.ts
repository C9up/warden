import type { AppContext } from '@c9up/ream'
import { AuthManager } from './AuthManager.js'

export default class WardenProvider {
  constructor(protected app: AppContext) {}

  register() {
    this.app.container.singleton(AuthManager, () => {
      const config = this.app.config.get<{ defaultStrategy?: string }>('auth')
      return new AuthManager({
        defaultStrategy: config?.defaultStrategy ?? 'jwt',
        strategies: {},
      })
    })
  }

  async boot() {}
  async start() {}
  async ready() {}
  async shutdown() {}
}
