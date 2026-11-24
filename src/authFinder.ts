/**
 * Timing-safe credential lookup — the counterpart of the upstream
 * `withAuthFinder` mixin's `verifyCredentials`, without the ORM.
 *
 * Why it exists: a login that returns early for an unknown account answers in
 * microseconds, and one that verifies a password hash for a known account
 * answers in ~100 ms. That difference alone lets an anonymous caller list the
 * registered emails, with no rate limit to bypass. The counter-measure is to
 * run the same verification for an unknown uid too, and to fail every case
 * with the same error.
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

import { randomBytes } from "node:crypto";
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
	 * an unknown uid runs the same verification a known one does. Every
	 * failure throws {@link E_INVALID_CREDENTIALS} — a password the hasher
	 * refuses (too long, for one) included. Only a hasher that cannot hash at
	 * all (its native binary is missing) throws its own error.
	 */
	verifyCredentials(uid: string, password: string): Promise<User>;
	/**
	 * Whether `password` matches `user`'s stored hash. `false` for a user
	 * without one and for a password the hasher refuses.
	 */
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

	// A password nobody can submit, and the hash this hasher makes of it: what
	// a sign-in is verified against when there is no stored hash to verify.
	// 43 bytes, under the limit of every hasher (bcrypt stops at 72).
	const decoyPassword = randomBytes(32).toString("base64url");
	let decoy: Promise<string> | undefined;
	const decoyHash = (): Promise<string> => {
		decoy ??= (async () => hash.make(decoyPassword))().catch(
			(error: unknown) => {
				// Not kept: the next sign-in asks the hasher again.
				decoy = undefined;
				throw error;
			},
		);
		return decoy;
	};

	/** Whether the hasher verifies a hash it made itself: it is in service. */
	const hasherInService = async (): Promise<boolean> => {
		try {
			return await hash.verify(await decoyHash(), decoyPassword);
		} catch {
			return false;
		}
	};

	/**
	 * The one verification every sign-in runs, whatever the lookup found.
	 *
	 * NAMED DEVIATION — upstream pays `hash.make(password)` for an unknown uid.
	 * That equals a known uid's `hash.verify(stored, password)` only while
	 * `make` accepts every password, which upstream's hashers do. A hasher
	 * with a length limit (sigil: 1024 bytes, 72 for bcrypt) throws from
	 * `make` and answers `false`, without hashing, from `verify`: the two
	 * branches then differ by their error and by their cost, and one request
	 * per email lists the accounts. So an unknown uid and a row without a hash
	 * make the SAME call a known uid makes, `verify`, against a decoy hash of
	 * the same hasher: whatever the hasher does with the password, it does it
	 * on the three branches alike.
	 *
	 * A `verify` that throws is settled the same way on every branch: the
	 * hasher is asked to verify its own decoy. It does — the password (or the
	 * stored hash) is what it refused, a credential that does not match, and
	 * that check cost one hash everywhere. It does not — the hasher is out of
	 * service, and its error propagates as the crash it is.
	 */
	const matches = async (
		stored: string | undefined,
		password: string,
	): Promise<boolean> => {
		const against = stored ?? (await decoyHash());
		let matched: boolean;
		try {
			matched = await hash.verify(against, password);
		} catch (refusal) {
			if (await hasherInService()) return false;
			throw refusal;
		}
		// The decoy never authenticates, whatever the hasher answered.
		return matched === true && stored !== undefined;
	};

	// NAMED DEVIATION — upstream throws a RuntimeException (a 500) for a row
	// without a hash. An account that signs in elsewhere (SSO) has none, and a
	// distinct 500 for it would tell a caller the account exists. It is a
	// password that does not match, verified at the cost of one that could.
	const verifyPassword = (user: User, password: string): Promise<boolean> =>
		matches(storedHash(user), password);

	const verifyCredentials = async (
		uid: string,
		password: string,
	): Promise<User> => {
		if (!uid || !password) throw new E_INVALID_CREDENTIALS();
		const user = await findForAuth(uid);
		if (user === null || user === undefined) {
			// The verification a known uid would cost, run for nothing: without
			// it the response time says whether the account exists.
			await matches(undefined, password);
			throw new E_INVALID_CREDENTIALS();
		}
		if (await matches(storedHash(user), password)) return user;
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
