/**
 * Teach ream's `Authenticators` interface what `ctx.auth.use(name)` returns.
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

declare module "@c9up/ream/types" {
	interface Authenticators {
		[guardName: string]: GuardAccessor;
	}
}

export type {};
