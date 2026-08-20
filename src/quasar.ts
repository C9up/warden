/**
 * Resolving a Redis connection by name, from `@c9up/quasar`.
 *
 * Warden does not depend on quasar: it is an optional peer, and this module
 * never imports it statically. The specifier is built at runtime so the
 * TypeScript build stays free of it too — a hard type import would make echo
 * unbuildable for anyone whose blacklist is in memory.
 *
 * The shape is checked before use rather than asserted, the same way warden
 * duck-types its host framework.
 */

import type { RedisLikeClient } from "./RedisBlacklistDriver.js";

/** The slice of quasar's manager this needs: a connection, by name. */
interface ConnectionSource {
	connection(name?: string): unknown;
}

function isConnectionSource(value: unknown): value is ConnectionSource {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof Reflect.get(value, "connection") === "function"
	);
}

function isRedisLikeClient(value: unknown): value is RedisLikeClient {
	if (typeof value !== "object" || value === null) return false;
	// The commands this driver actually issues. A connection missing one of
	// them would fail on the first revocation, far from the cause.
	const required = [
		"get",
		"set",
		"del",
		"exists",
		"keys",
		"sadd",
		"srem",
		"smembers",
		"expire",
		"ttl",
	];
	return required.every(
		(name) => typeof Reflect.get(value, name) === "function",
	);
}

/**
 * A resolver for `new RedisBlacklistDriver(quasarConnection())` — quasar is
 * loaded on the first revocation check, not at config time.
 */
export function quasarConnection(
	name?: string,
): () => Promise<RedisLikeClient> {
	return async () => {
		const specifier = "@c9up/quasar/services/main";
		let loaded: unknown;
		try {
			loaded = await import(/* @vite-ignore */ specifier);
		} catch (cause) {
			throw new Error(
				`Warden: the "${name ?? "default"}" blacklist asks for a quasar connection, but @c9up/quasar is not installed.\n` +
					"  pnpm add @c9up/quasar",
				{ cause },
			);
		}

		const manager = isConnectionSource(loaded)
			? loaded
			: Reflect.get(Object(loaded), "default");
		if (!isConnectionSource(manager)) {
			throw new Error(
				"Warden: @c9up/quasar/services/main did not expose a connection() manager",
			);
		}

		const connection = manager.connection(name);
		if (!isRedisLikeClient(connection)) {
			throw new Error(
				`Warden: quasar connection "${name ?? "default"}" does not carry the commands this blacklist needs`,
			);
		}
		return connection;
	};
}
