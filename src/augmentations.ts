/**
 * Teach ream's `Authenticators` and `ContainerBindings` interfaces what warden
 * puts in them.
 *
 * `Authenticators` says what `ctx.auth.use(name)` returns; `ContainerBindings`
 * says what `container.make('auth')` returns. Only the first was filled in —
 * ream's own comment on `ContainerBindings` names `auth` (warden) as reaching
 * it by augmentation from here, and nothing did, so resolving by the string
 * token answered `unknown` and every call site had to assert a type it could
 * not prove.
 *
 * ream declares that interface empty on purpose — it owns no auth package, so
 * it cannot know an application's guards, and `use()` falls back to `unknown`
 * until something fills it in. Warden is that something.
 *
 * An index signature rather than an enumeration of names, because that is the
 * truth here: `Authenticator.use()` accepts any guard name and always hands
 * back a `GuardAccessor`. AdonisJS enumerates instead, since each of its
 * guards has a distinct type; warden's do not.
 *
 * Loaded from the package barrel, so importing warden anywhere in the app is
 * enough — an application writes no `declare module` of its own.
 */

// Referenced so the augmentation below resolves the module it augments.
import type {} from "@c9up/ream/types";
import type { GuardAccessor } from "./Authenticator.js";
import type { AuthManager } from "./AuthManager.js";
import type { MfaManager } from "./mfa/MfaManager.js";

declare module "@c9up/ream/types" {
	interface Authenticators {
		[guardName: string]: GuardAccessor;
	}

	interface ContainerBindings {
		/** The auth manager, bound by `WardenProvider`. */
		"warden.auth": AuthManager;
		/**
		 * The same binding under the name it had before the token carried its
		 * package. Kept bound so an existing `container.make(...)` resolves.
		 */
		auth: AuthManager;
		/** The MFA manager — bound only when `config.mfa.manager` is set. */
		"warden.mfa": MfaManager;
		/**
		 * The same binding under the name it had before the token carried its
		 * package. Kept bound so an existing `container.make(...)` resolves.
		 */
		mfa: MfaManager;
	}
}
