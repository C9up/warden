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
import {
	decodeTokenValue,
	mintRememberMeToken,
	type RememberMeTokenDriver,
	verifyAndRecycleRememberMeToken,
} from "../RememberMeToken.js";

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
	/**
	 * Turn on "keep me signed in". Adonis calls the equivalent flag
	 * `useRememberMeTokens`; without a driver there is nowhere to persist the
	 * token, so passing one IS the opt-in.
	 */
	rememberMeTokens?: RememberMeTokenDriver;
	/**
	 * How long a remember-me token lives. Adonis defaults to two years, and a
	 * number here is SECONDS (`durationToSeconds` semantics).
	 */
	rememberMeAge?: number;
	/**
	 * Cookie name holding the token. Adonis derives `remember_<guard>`; the
	 * default matches the `web` guard an app is most likely migrating.
	 */
	rememberMeCookieName?: string;
}

/** Two years, Adonis' `rememberMeTokensAge` default. */
const DEFAULT_REMEMBER_AGE_SECONDS = 63_072_000;

export class SessionStrategy implements AuthStrategy {
	name = "session";
	#config: SessionStrategyConfig;
	#sessionKey: string;
	#viaRemember = false;
	#loggedOut = false;
	#attemptedViaRemember = false;

	constructor(config: SessionStrategyConfig) {
		this.#config = config;
		this.#sessionKey = config.sessionKey ?? "auth_user_id";
	}

	/** The cookie the remember-me token travels in. */
	get rememberMeCookieName(): string {
		return this.#config.rememberMeCookieName ?? "remember_web";
	}

	/** Whether "keep me signed in" is wired at all. */
	get usesRememberMeTokens(): boolean {
		return this.#config.rememberMeTokens !== undefined;
	}

	/**
	 * Whether the current user was revived from a remember-me cookie rather
	 * than signing in (AdonisJS `viaRemember`).
	 *
	 * This is the distinction that lets an app demand the password again before
	 * something sensitive — changing an email, spending money, deleting an
	 * account. Nothing reported it, so a session restored from a cookie looked
	 * exactly like one where the user had just typed their password.
	 */
	get viaRemember(): boolean {
		return this.#viaRemember;
	}

	/**
	 * Whether a remember-me token was even tried on this request (AdonisJS
	 * `attemptedViaRemember`) — true whether or not it worked.
	 */
	get attemptedViaRemember(): boolean {
		return this.#attemptedViaRemember;
	}

	/**
	 * Whether `logout()` ran on this guard (AdonisJS `isLoggedOut`).
	 *
	 * A handler that logs out and then keeps working — clearing a cart, writing
	 * an audit line — could not tell that the session was already gone.
	 */
	get isLoggedOut(): boolean {
		return this.#loggedOut;
	}

	/** The session key the user id is stored under (AdonisJS `sessionKeyName`). */
	get sessionKeyName(): string {
		return this.#sessionKey;
	}

	/** The cookie key the remember-me token is stored under (AdonisJS `rememberMeKeyName`). */
	get rememberMeKeyName(): string {
		return this.rememberMeCookieName;
	}

	#rememberMeAge(): number {
		return this.#config.rememberMeAge ?? DEFAULT_REMEMBER_AGE_SECONDS;
	}

	/**
	 * Mint a remember-me token for `user` and return the cookie value the caller
	 * must set. `null` when the feature is not wired.
	 */
	async issueRememberMeToken(user: UserPayload): Promise<string | null> {
		const driver = this.#config.rememberMeTokens;
		if (!driver) return null;
		const minted = mintRememberMeToken(user.id, this.#rememberMeAge());
		await driver.create(minted.stored);
		return minted.value;
	}

	/**
	 * Authenticate from a remember-me cookie, and RECYCLE it: the returned
	 * `cookieValue` must replace the one the browser holds.
	 *
	 * The user is re-read through `findUser`, never trusted from the token — a
	 * token outlives the row it points at, and a deleted or disabled account
	 * must not walk back in through a cookie.
	 */
	async authenticateViaRememberMeToken(
		cookieValue: unknown,
	): Promise<{ user: UserPayload; cookieValue: string } | null> {
		const driver = this.#config.rememberMeTokens;
		if (!driver) return null;
		this.#attemptedViaRemember = true;

		const recycled = await verifyAndRecycleRememberMeToken(
			driver,
			cookieValue,
			this.#rememberMeAge(),
		);
		if (!recycled) return null;

		const user = await this.#config.findUser(recycled.userId);
		if (!user) return null;

		this.#viaRemember = true;
		return { user, cookieValue: recycled.value };
	}

	/**
	 * Drop the token behind `cookieValue`. Called on logout so the persistent
	 * credential dies with the session — Adonis deletes the row too.
	 */
	async revokeRememberMeToken(cookieValue: unknown): Promise<void> {
		const driver = this.#config.rememberMeTokens;
		if (!driver) return;
		const decoded = decodeTokenValue(cookieValue);
		if (!decoded) return;
		await driver.delete(decoded.identifier);
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
		this.#loggedOut = false;
		// A password was typed: this session is no longer "via remember", even
		// if a cookie was tried earlier in the same request. Without the reset
		// the flag would stay true and a re-auth prompt would never fire.
		this.#viaRemember = false;
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

	/**
	 * Logout — remove the user id from the session.
	 *
	 * The remember-me token is revoked separately through
	 * {@link revokeRememberMeToken}, because only the caller holds the cookie.
	 */
	async logout(session: SessionStore): Promise<void> {
		session.forget(this.#sessionKey);
		this.#viaRemember = false;
		this.#attemptedViaRemember = false;
		this.#loggedOut = true;
	}
}
