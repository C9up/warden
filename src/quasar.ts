/**
 * Resolving a Redis connection by name, from `@c9up/quasar`.
 *
 * The loading, the shape check and the messages are the same in every package
 * that offers a Redis-backed option, so they are vendored rather than written
 * again: `src/vendor/quasarConnection.ts`, generated from one source. What is
 * specific to this package — the commands it issues, and what it does with
 * them — stays here, because that is the part a reader needs.
 */

import type { RedisLikeClient } from "./RedisBlacklistDriver.js";
import { quasarConnection as loadQuasarConnection } from "./vendor/quasarConnection.js";

// Only what the driver documents itself as needing: `set` with an "EX" ttl,
// and `exists`. Demanding key scans here would reject a client that works.
const REQUIRED = ["set", "exists"] as const;

/**
 * A resolver — quasar is loaded on first use, not at config time.
 */
export function quasarConnection(
	name?: string,
): () => Promise<RedisLikeClient> {
	return async () =>
		loadQuasarConnection<RedisLikeClient>({
			pkg: "warden",
			name,
			required: REQUIRED,
			what: "the token blacklist",
			raise: (_reason, message, cause) => new Error(message, { cause }),
		});
}
