import type { AuthState } from "@c9up/ream";
import { describe, expect, it } from "vitest";
import type { GuardAccessor } from "../src/Authenticator.js";
import "../src/index.js";

/**
 * `ctx.auth.use(name)` came back as `unknown`, so reaching a guard needed a
 * cast that lies about a contract warden does not own — applications worked
 * around it through `authenticateUsing(['session'])`.
 *
 * warden augments ream's `Authenticators` interface now, so the guard type
 * flows through. The assignment below is the test: it fails to COMPILE if the
 * augmentation stops being honoured, which is how this regressed before —
 * silently, with everything still passing at runtime.
 */
describe("ctx.auth.use > typing", () => {
	it("hands back a GuardAccessor for any guard name", () => {
		const auth: AuthState = { isAuthenticated: false };
		const guard: GuardAccessor | undefined = auth.use?.("session");
		expect(guard).toBeUndefined();
	});
});
