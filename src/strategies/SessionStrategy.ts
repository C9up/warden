/**
 * Session-based authentication strategy.
 *
 * AdonisJS session guard pattern:
 *   login stores userId in session, subsequent requests check session.
 *
 * @implements MISS-7
 */

import type {
	AuthClientResponse,
	AuthResult,
	AuthStrategy,
	UserPayload,
} from "../AuthManager.js";
import { WardenError } from "../errors.js";

export interface SessionStore {
	get(key: string): unknown;
	/**
	 * Write a value. Named `put` to match the AdonisJS `Session` API (and Ream's
	 * `Session`), so a Ream `Session` satisfies this contract structurally with
	 * no adapter. (Was `set` — which Ream's Session does not implement, so login
	 * threw `session.set is not a function` at runtime.)
	 */
	put(key: string, value: unknown): void;
	forget(key: string): void;
	/**
	 * Rotate the session id while preserving the data. REQUIRED to mitigate
	 * session fixation (CWE-384) at login. Ream's `Session.regenerate()`
	 * implements this; adapters around other session stores MUST too. The
	 * default ream → warden plumbing exposes the `Session` instance
	 * directly so this is wired automatically.
	 */
	regenerate(): void;
}

export interface SessionStrategyConfig {
	sessionKey?: string;
	findUser: (id: string | number) => Promise<UserPayload | null>;
}

export class SessionStrategy implements AuthStrategy {
	name = "session";
	#config: SessionStrategyConfig;
	#sessionKey: string;

	constructor(config: SessionStrategyConfig) {
		this.#config = config;
		this.#sessionKey = config.sessionKey ?? "auth_user_id";
	}

	/** Authenticate via email/password — stores user ID in session. */
	async authenticate(
		_credentials: { email: string; password: string },
		_context?: { session?: SessionStore },
	): Promise<AuthResult> {
		// Session strategy doesn't handle password verification — that's done
		// by the caller. We throw a typed sentinel WardenError so AuthManager's
		// try/catch (which swallows generic errors into a soft AuthResult)
		// re-throws this one — the design boundary stays unmissable even when
		// a caller routes through `authManager.authenticate()` instead of
		// `strategy.authenticate()` directly.
		throw new WardenError(
			"USE_LOGIN",
			"SessionStrategy has no credential step. Verify the password yourself, then start the session via authManager.login(user, session) (or ctx.auth.use('session').login(user)).",
			{
				hint: "Verify the password yourself (e.g. via @c9up/sigil Hash.verify), then call authManager.login(user, session) — SessionStrategy.login(user, session) also works directly.",
			},
		);
	}

	/** Verify session — check if user ID is stored in session. */
	async verify(_token: string): Promise<AuthResult> {
		return {
			authenticated: false,
			error:
				"SessionStrategy.verify() requires context. Use verifyWithContext().",
		};
	}

	/** Verify session with context — check if user ID is stored in session. */
	async verifyWithContext(
		_token: string,
		context?: { session?: SessionStore },
	): Promise<AuthResult> {
		if (!context?.session) return { authenticated: false, error: "No session" };
		const userId = context.session.get(this.#sessionKey);
		if (!userId) return { authenticated: false, error: "No session user" };
		if (typeof userId !== "string" && typeof userId !== "number")
			return { authenticated: false, error: "Invalid session data" };
		const user = await this.#config.findUser(userId);
		if (!user) return { authenticated: false, error: "User not found" };
		return { authenticated: true, user };
	}

	/**
	 * Login a user — store their ID in the session.
	 *
	 * Rotates the session id BEFORE writing the authenticated user id, so an
	 * attacker who fed the victim a pre-login session cookie (classic
	 * session-fixation attack, CWE-384) ends up holding a now-discarded id
	 * while the victim continues under a fresh one. The driver-side cookie
	 * migration is handled by Ream's `SessionMiddleware` on the response
	 * path — see `wasRegenerated()` there.
	 */
	async login(user: UserPayload, session: SessionStore): Promise<void> {
		session.regenerate();
		session.put(this.#sessionKey, user.id);
	}

	/**
	 * The session entry a test client needs to be `user` (AdonisJS
	 * `authenticateAsClient`).
	 *
	 * Returns the same key `login()` writes, so the request is authenticated by
	 * the guard's own logic rather than by the test knowing where the id lives.
	 */
	authenticateAsClient(user: UserPayload): AuthClientResponse {
		return { session: { [this.#sessionKey]: user.id } };
	}

	/** Logout — remove user ID from session. */
	async logout(session: SessionStore): Promise<void> {
		session.forget(this.#sessionKey);
	}
}
