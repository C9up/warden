/**
 * `@c9up/warden/silent-auth` — the lazy default-class entry for the silent auth
 * middleware, so apps register it AdonisJS-style:
 *
 *   // start/kernel.ts — BEFORE the enforcing `@c9up/warden/middleware`
 *   server.use([() => import('@c9up/warden/silent-auth')])
 *
 * Ream's lazy middleware resolver does `new mod.default().handle(ctx, next)`.
 * The logic lives in `./middleware` (alongside `wardenMiddleware`, sharing the
 * same strategy-verification path); this is the thin default-class wrapper, the
 * same shape `./middleware` exposes for `WardenMiddleware`.
 */
import { silentAuth, type WardenContext } from "./middleware.js";

export { silentAuth };

export default class SilentAuthMiddleware {
	handle(ctx: WardenContext, next: () => Promise<void> | void): Promise<void> {
		return silentAuth(ctx, next);
	}
}
