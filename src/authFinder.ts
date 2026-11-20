/**
 * Timing-safe credential lookup — the counterpart of the upstream
 * `withAuthFinder` mixin's `verifyCredentials`, without the ORM.
 *
 * Why it exists: a login that returns early for an unknown account answers in
 * microseconds, and one that verifies a password hash for a known account
 * answers in ~100 ms. That difference alone lets an anonymous caller list the
 * registered emails, with no rate limit to bypass. The counter-measure is to pay
 * one hash for an unknown uid too, and to fail every case with the same error.
 *
 * Upstream mixes the methods into a Lucid model; warden knows no ORM, so the
 * lookup is passed in (`findForAuth`) and the methods come back as plain
 * functions, bound, ready to hand to a guard:
 *
 * ```ts
 * const users = authFinder({ hash, findForAuth: (email) => User.findBy('email', email) })
 * jwtGuard({ secret, findUser, verifyCredentials: users.verifyCredentials })
 * ```
 */

import { E_INVALID_CREDENTIALS } from "./errors.js";

/** What `authFinder` hashes with — `make` and `verify`, AdonisJS argument order. */
export interface AuthFinderHasher {
	make(value: string): Promise<string>;
	verify(hashedValue: string, plainValue: string): Promise<boolean>;
}

export interface AuthFinderOptions<User extends object> {
	/** The hasher the passwords were made with (a sigil `Hash`, for one). */
	hash: AuthFinderHasher;
	/**
	 * Find the user a sign-in names — by email, username, whatever the uid is.
	 * `null` or `undefined` for none.
	 */
	findForAuth: (uid: string) => Promise<User | null | undefined>;
	/** The property the password hash lives under. Default `password`. */
	passwordColumnName?: string;
}

export interface AuthFinder<User extends object> {
	/**
	 * Find the user by `uid` and verify `password`. Safe from timing attacks:
	 * an unknown uid pays the same one hash a known one does. Every failure
	 * throws {@link E_INVALID_CREDENTIALS}.
	 */
	verifyCredentials(uid: string, password: string): Promise<User>;
	/** Whether `password` matches `user`'s stored hash. */
	verifyPassword(user: User, password: string): Promise<boolean>;
}

export function authFinder<User extends object>(
	options: AuthFinderOptions<User>,
): AuthFinder<User> {
	const { hash, findForAuth } = options;
	const column = options.passwordColumnName ?? "password";

	const storedHash = (user: User): string | undefined => {
		const value: unknown = Reflect.get(user, column);
		return typeof value === "string" && value.length > 0 ? value : undefined;
	};

	const verifyPassword = async (
		user: User,
		password: string,
	): Promise<boolean> => {
		const hashed = storedHash(user);
		if (hashed === undefined) {
			// NAMED DEVIATION — upstream throws a RuntimeException (a 500) for
			// a row without a hash. An account that signs in elsewhere (SSO)
			// has none, and a distinct 500 for it would tell a caller the
			// account exists. It is a password that does not match, and it
			// pays the hash a match would have cost.
			await hash.make(password);
			return false;
		}
		return hash.verify(hashed, password);
	};

	const verifyCredentials = async (
		uid: string,
		password: string,
	): Promise<User> => {
		if (!uid || !password) throw new E_INVALID_CREDENTIALS();
		const user = await findForAuth(uid);
		if (user === null || user === undefined) {
			// The hash a known uid would cost, paid for nothing: without it the
			// response time says whether the account exists.
			await hash.make(password);
			throw new E_INVALID_CREDENTIALS();
		}
		if (await verifyPassword(user, password)) return user;
		throw new E_INVALID_CREDENTIALS();
	};

	return { verifyCredentials, verifyPassword };
}

/**
 * A guard's `verifyCredentials` answers a wrong credential with `null`; one
 * built on {@link authFinder} throws {@link E_INVALID_CREDENTIALS} instead, as
 * upstream's does. Both mean the same rejection, so a guard reads them alike.
 *
 * NAMED DEVIATION — upstream's user provider swallows EVERY error into `null`,
 * so a database outage reads as a wrong password. Only E_INVALID_CREDENTIALS
 * is a rejection here; anything else propagates and the auth manager reports it
 * as the strategy crash it is.
 */
export async function rejectedAsNull<User>(
	verification: Promise<User | null>,
): Promise<User | null> {
	try {
		return await verification;
	} catch (error) {
		if (error instanceof E_INVALID_CREDENTIALS) return null;
		throw error;
	}
}
