/**
 * Wraps a sensitive value so it never leaks through a log, `JSON.stringify`, or
 * `util.inspect`. Read it back deliberately with {@link Secret.release}.
 *
 * AdonisJS takes this from `@adonisjs/core/helpers`, and its `RememberMeToken`
 * hands secrets out wrapped in one. Warden carries its own copy rather than
 * importing `@c9up/ream`: it has no runtime dependencies and ships a standalone
 * entry point, so reaching for a peer here would break the framework-free mode.
 * Same reason every native package carries its own platform map.
 */
const REDACTED = "[redacted]";

export class Secret<T> {
	readonly #value: T;
	readonly #keyword: string;

	constructor(value: T, redactedKeyword: string = REDACTED) {
		this.#value = value;
		this.#keyword = redactedKeyword;
	}

	/** Redacted placeholder, so `JSON.stringify` never emits the secret. */
	toJSON(): string {
		return this.#keyword;
	}

	/** Redacted placeholder for string coercion and template literals. */
	toString(): string {
		return this.#keyword;
	}

	/** Redacted placeholder for `console.log` / `util.inspect`. */
	[Symbol.for("nodejs.util.inspect.custom")](): string {
		return this.#keyword;
	}

	/** Release the underlying value — the one deliberate way to read it. */
	release(): T {
		return this.#value;
	}
}
