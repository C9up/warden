/**
 * How warden's errors write themselves to a response (their `handle`). The
 * context is read structurally — warden imports no host — and what a host may
 * lack (a session, a redirect builder, content negotiation) is read when it is
 * there.
 */

/** What an `E_UNAUTHORIZED_ACCESS` response is written with. */
export interface UnauthorizedAccessContext {
	request: { headers(): Readonly<Record<string, string>> };
	response: {
		status(code: number): unknown;
		json(data: unknown): void;
		/** Set a response header: the `WWW-Authenticate` challenge of a 401. */
		header?(name: string, value: string): unknown;
		/** Redirect to `url`: the login route of a session guard. */
		redirect?(url: string): unknown;
	};
}

/** The fields of an `E_UNAUTHORIZED_ACCESS` its response is built from. */
interface UnauthorizedAccess {
	status: number;
	code?: string;
	redirectTo?: string;
	challenge?: string;
}

/**
 * An HTML request against a session guard that carries a `redirectTo` is
 * redirected to the login route; anything else gets the `WWW-Authenticate`
 * challenge when the guard has one (Basic), and
 * `401 { error: { code, message } }`. Always fail-closed.
 */
export function renderUnauthorizedAccess(
	ctx: UnauthorizedAccessContext,
	error: UnauthorizedAccess,
	message: string,
): void {
	const accept = ctx.request.headers().accept ?? "";
	const wantsHtml = accept.includes("text/html");
	if (wantsHtml && error.redirectTo && ctx.response.redirect) {
		ctx.response.redirect(error.redirectTo);
		return;
	}
	if (error.challenge !== undefined) {
		ctx.response.header?.call(
			ctx.response,
			"WWW-Authenticate",
			error.challenge,
		);
	}
	ctx.response.status(error.status);
	ctx.response.json({ error: { code: error.code, message } });
}

/** What a negotiated error response is written with. */
export interface NegotiatedErrorContext {
	request: {
		/** Content negotiation: the first of `types` the client accepts. */
		accepts?<T extends string>(types: T[]): T | null;
		method?(): string;
	};
	response: {
		status(code: number): unknown;
		/** Write the body as is. Without it, {@link json} writes it. */
		send?(body: unknown): unknown;
		json?(data: unknown): unknown;
	};
}

/** The formats an error is rendered in, in upstream's order. */
const RESPONSE_FORMATS = ["html", "application/vnd.api+json", "json"];

function isObject(value: unknown): value is object {
	return typeof value === "object" && value !== null;
}

/** Call `name` on `target` when it is there: the host may implement only some. */
function callIfFunction(
	target: object,
	name: string,
	...args: unknown[]
): void {
	const fn: unknown = Reflect.get(target, name);
	if (typeof fn === "function") Reflect.apply(fn, target, args);
}

/** Write `body` with the response's `send`, or its `json` when it has none. */
function write(
	ctx: NegotiatedErrorContext,
	status: number,
	body: unknown,
): void {
	ctx.response.status(status);
	if (typeof ctx.response.send === "function") ctx.response.send(body);
	else ctx.response.json?.(body);
}

/**
 * Write an error by content negotiation: `{ errors: [{ message }] }` for
 * JSON, a JSON:API error object for JSON:API. For HTML (or a client that
 * accepts none of them), a request with a session — and `redirectBack` —
 * gets the form flashed back (minus `flashExcept`), the message flashed as
 * `error` and under the code, and a redirect back; any other the message as
 * text.
 */
export function renderNegotiated(
	ctx: NegotiatedErrorContext,
	error: { status: number; code: string; message: string },
	options: { flashExcept: string[]; redirectBack: boolean },
): void {
	const { status, code, message } = error;
	const format =
		typeof ctx.request.accepts === "function"
			? ctx.request.accepts(RESPONSE_FORMATS)
			: null;
	if (format === "json") {
		write(ctx, status, { errors: [{ message }] });
		return;
	}
	if (format === "application/vnd.api+json") {
		write(ctx, status, { errors: [{ code, title: message }] });
		return;
	}
	const session: unknown = Reflect.get(ctx, "session");
	const redirect: unknown = Reflect.get(ctx.response, "redirect");
	if (
		options.redirectBack &&
		isObject(session) &&
		typeof redirect === "function"
	) {
		callIfFunction(session, "flashExcept", options.flashExcept);
		callIfFunction(session, "flash", "error", message);
		callIfFunction(session, "flashErrors", { [code]: message });
		Reflect.apply(redirect, ctx.response, ["back", true]);
		return;
	}
	write(ctx, status, message);
}
