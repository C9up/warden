/**
 * Emit an authorization event without letting the listener come back.
 *
 * `@adonisjs/events` declares `emit(): Promise<void>` and rethrows when a
 * listener fails and the application registered no error handler. Nobody
 * awaits an authorization event — it is an audit trail, not a participant in
 * the decision — so that rejection had nowhere to go and ended the process
 * over a logger.
 *
 * The emitter is invoked INSIDE the async function rather than before it:
 * `Promise.resolve(emit(...))` runs `emit` first, so a synchronous throw would
 * still escape. The call itself stays synchronous, because an async body runs
 * to its first `await` — the deferral is only the failure handling.
 */
export function emitSafely(
	emitter: { emit: (event: string, payload: unknown) => unknown } | undefined,
	event: string,
	payload: unknown,
): void {
	if (emitter === undefined) return;
	void (async () => emitter.emit(event, payload))().catch((error: unknown) => {
		process.stderr.write(
			`[warden] '${event}' listener failed: ${
				error instanceof Error ? error.message : String(error)
			}\n`,
		);
	});
}
