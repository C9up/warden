/**
 * Duration parsing for token lifetimes.
 *
 * Upstream's `expiresIn` takes either a number of seconds or a human string
 * (`'1h'`, `'7 days'`), and a config copied from an Adonis app carries the
 * string form. Accepting only the number meant such a config was rejected for
 * a reason that had nothing to do with authentication.
 *
 * The unit table is the one `@c9up/echo` parses its TTLs with, transcribed
 * rather than imported: every package here installs on its own, so a shared
 * helper would be a dependency edge bought for forty lines. Transcribed, not
 * reinvented — two packages that disagreed on what `'1d'` means would be worse
 * than either one being wrong alone.
 */

const UNIT_SECONDS: Record<string, number> = {
	ms: 1 / 1000,
	msec: 1 / 1000,
	msecs: 1 / 1000,
	millisecond: 1 / 1000,
	milliseconds: 1 / 1000,
	s: 1,
	sec: 1,
	secs: 1,
	second: 1,
	seconds: 1,
	m: 60,
	min: 60,
	mins: 60,
	minute: 60,
	minutes: 60,
	h: 3600,
	hr: 3600,
	hrs: 3600,
	hour: 3600,
	hours: 3600,
	d: 86_400,
	day: 86_400,
	days: 86_400,
	w: 604_800,
	week: 604_800,
	weeks: 604_800,
};

const DURATION_RE = /^\s*(\d+(?:\.\d+)?)\s*([a-z]+)?\s*$/i;

/**
 * A token lifetime: seconds as a number, or a human duration string.
 *
 * A bare number is SECONDS, not milliseconds — that is what `expiresInSeconds`
 * has always meant here, and a silent change of unit is the kind of thing
 * nobody notices until tokens live a thousand times too long.
 */
export type TokenDuration = number | string;

/**
 * Parse a human duration into seconds.
 *
 * Rejects rather than guesses: a lifetime that silently reads as zero, or as
 * the wrong unit, is an authentication bug that surfaces as "users are
 * randomly logged out" weeks later.
 */
export function parseDurationSeconds(value: string): number {
	const match = DURATION_RE.exec(value);
	if (!match) {
		throw new TypeError(`Warden: invalid duration "${value}"`);
	}
	const amount = Number(match[1]);
	const unit = match[2]?.toLowerCase();
	if (unit === undefined) return amount;
	const factor = UNIT_SECONDS[unit];
	if (factor === undefined) {
		throw new TypeError(
			`Warden: unknown duration unit "${unit}" in "${value}"`,
		);
	}
	return amount * factor;
}

/**
 * Resolve a lifetime to seconds.
 *
 * `expiresIn` is upstream's spelling and wins when both are given; a config
 * that sets the two disagrees with itself, and the portable name is the one to
 * honour.
 */
export function resolveExpiresInSeconds(
	expiresIn: TokenDuration | undefined,
	expiresInSeconds: number | undefined,
	fallbackSeconds: number,
): number {
	const chosen = expiresIn ?? expiresInSeconds ?? fallbackSeconds;
	const seconds =
		typeof chosen === "number" ? chosen : parseDurationSeconds(chosen);
	if (!Number.isFinite(seconds) || seconds <= 0) {
		throw new TypeError(
			`Warden: token lifetime must be a positive duration, got ${JSON.stringify(chosen)}`,
		);
	}
	return seconds;
}
