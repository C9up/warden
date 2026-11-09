import { WardenError } from "./errors.js";

/** The only surface warden needs of a template engine. */
export interface TemplateEngineLike {
	registerTag(tag: {
		tagName: string;
		block: boolean;
		seekable: boolean;
		compile(
			parser: unknown,
			buffer: { writeRaw(text: string): void },
			token: {
				properties: { jsArg: string };
				renderBody(): string | Promise<string>;
				evaluate(expression: string): unknown;
			},
		): void | Promise<void>;
	}): void;
}

/**
 * Register `@can` / `@cannot`, as AdonisJS's bouncer publishes them. A
 * migrated template keeps `@can('PostPolicy.edit', post) … @endcan` unchanged.
 *
 * Both are BLOCK tags and both AWAIT — the check returns a promise — so they
 * render on the async path and raise on a synchronous one, matching upstream
 * (which emits `await bouncer.can(...)`). The checks themselves come from
 * `ctx.bouncer.templateHelpers`, shared into the view per request.
 */
export function registerBouncerTemplateTags(engine: TemplateEngineLike): void {
	for (const tagName of ["can", "cannot"] as const) {
		engine.registerTag({
			tagName,
			block: true,
			seekable: true,
			async compile(_parser, buffer, token) {
				// The shared bag lives in the render scope under `bouncer`.
				const bouncer = token.evaluate(
					"typeof bouncer === 'undefined' ? undefined : bouncer",
				);
				const check = Reflect.get(Object(bouncer), tagName);
				if (typeof check !== "function") {
					// No bouncer on this request: deny rather than render an
					// unguarded body.
					return;
				}
				const args = token.evaluate(`[${token.properties.jsArg}]`);
				const allowed = await check.apply(
					bouncer,
					Array.isArray(args) ? args : [],
				);
				if (allowed === true) buffer.writeRaw(await token.renderBody());
			},
		});
	}
}

/** Loads the template engine package. Swappable so a test needs no engine. */
export type EnginePackageLoader = () => Promise<unknown>;

const loadInker: EnginePackageLoader = () => {
	// Built rather than written inline: inker is an OPTIONAL peer, and a
	// literal `import("@c9up/inker")` makes a bundler resolve it at build time
	// for an application that never installed it. Computed, it only runs
	// behind the `usingInker` flag.
	const specifier = "@c9up/inker";
	return import(/* @vite-ignore */ specifier);
};

function unusable(detail: string): WardenError {
	return new WardenError(
		"E_WARDEN_TEMPLATE_ENGINE_UNUSABLE",
		`The template engine is installed but @can / @cannot cannot be registered: ${detail}`,
		{
			hint: "`@c9up/inker` must default-export its plugin registrar (`inker.use(plugin)`), whose plugins receive an engine with `registerTag()`.",
		},
	);
}

/**
 * Publish the bouncer tags the way AdonisJS's bouncer does with Edge: through
 * the engine package's MODULE SINGLETON (`inker.use(plugin)`), guarded by the
 * host's `usingInker` flag — never by resolving a container binding. `use()`
 * queues the plugin and the engine runs it before its next render, whenever
 * the engine was built.
 *
 * Returns whether the tags were handed over. A registrar or an engine of the
 * wrong shape is an error, not a skip: an unregistered `@can` would render as
 * plain text and show the guarded body's markup to everyone.
 */
export async function installBouncerTemplateTags(
	usingInker: boolean,
	load: EnginePackageLoader = loadInker,
): Promise<boolean> {
	if (!usingInker) return false;
	const module: unknown = await load();
	const registrar =
		typeof module === "object" && module !== null
			? Reflect.get(module, "default")
			: undefined;
	const use = Reflect.get(Object(registrar), "use");
	if (typeof use !== "function") {
		throw unusable("its default export has no use()");
	}
	use.call(registrar, (engine: unknown) => {
		const register = Reflect.get(Object(engine), "registerTag");
		if (typeof register !== "function") {
			throw unusable("the engine has no registerTag()");
		}
		registerBouncerTemplateTags({
			registerTag: (tag) => {
				register.call(engine, tag);
			},
		});
	});
	return true;
}
