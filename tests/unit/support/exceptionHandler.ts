/**
 * Run a middleware as the host does: an error thrown in the chain reaches the
 * exception handler, which lets an error that renders itself — one with a
 * `handle(error, ctx)`, such as `E_UNAUTHORIZED_ACCESS` or
 * `E_AUTHORIZATION_FAILURE` — answer on the same context. Any other error is
 * left to propagate.
 */

type Middleware<C> = (
	ctx: C,
	next: () => Promise<void> | void,
) => Promise<void>;

/**
 * Wrap `middleware` in the host's exception handler. `onHandled`, when given,
 * is told which error rendered itself, on which context.
 */
export function withExceptionHandler<C>(
	middleware: Middleware<C>,
	onHandled?: (error: object, ctx: C) => void,
): Middleware<C> {
	return async (ctx, next) => {
		try {
			await middleware(ctx, next);
		} catch (error) {
			if (typeof error !== "object" || error === null) throw error;
			const handle: unknown = Reflect.get(error, "handle");
			if (typeof handle !== "function") throw error;
			await Reflect.apply(handle, error, [error, ctx]);
			onHandled?.(error, ctx);
		}
	};
}

/**
 * A minimal `request.accepts` over the `Accept` header: the first of `types`
 * the header names, `null` when it names none of them.
 */
export function acceptsFrom(
	headers: Readonly<Record<string, string>>,
): <T extends string>(types: T[]) => T | null {
	const accept = headers.accept ?? "";
	return (types) => {
		for (const type of types) {
			const mime =
				type === "json"
					? "application/json"
					: type === "html"
						? "text/html"
						: type;
			if (accept.includes(mime)) return type;
		}
		return null;
	};
}
