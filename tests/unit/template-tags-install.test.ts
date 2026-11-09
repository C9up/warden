/**
 * `@can` / `@cannot` reach the template engine through the engine package's
 * module singleton (`inker.use(plugin)`), guarded by `usingInker` — never by
 * resolving a container binding, which is only usable after every provider
 * booted (and whose internals changed under it once already).
 */
import { describe, expect, it } from "vitest";
import {
	installBouncerTemplateTags,
	type TemplateEngineLike,
} from "../../src/templateTags.js";

type Tag = Parameters<TemplateEngineLike["registerTag"]>[0];
type Plugin = (engine: unknown) => void;

/** A registrar shaped like `@c9up/inker`'s default export: `use()` queues. */
function inkerLike() {
	const queued: Plugin[] = [];
	const registrar = {
		use(plugin: Plugin) {
			queued.push(plugin);
			return registrar;
		},
	};
	const tags = new Map<string, Tag>();
	return {
		load: async (): Promise<unknown> => ({ default: registrar }),
		boot: () => {
			for (const plugin of queued)
				plugin({ registerTag: (tag: Tag) => tags.set(tag.tagName, tag) });
		},
		tags,
	};
}

async function renderTag(
	tag: Tag | undefined,
	scope: Record<string, unknown>,
	jsArg: string,
): Promise<string> {
	if (tag === undefined) throw new Error("tag was never registered");
	let out = "";
	await tag.compile(
		undefined,
		{
			writeRaw: (text) => {
				out += text;
			},
		},
		{
			properties: { jsArg },
			renderBody: () => "BODY",
			evaluate: (expression) =>
				expression.startsWith("typeof bouncer")
					? scope.bouncer
					: JSON.parse(`[${jsArg.replace(/'/g, '"')}]`),
		},
	);
	return out;
}

describe("warden > installBouncerTemplateTags", () => {
	it("pushes @can and @cannot through use(), and they render", async () => {
		const inker = inkerLike();
		expect(await installBouncerTemplateTags(true, inker.load)).toBe(true);
		expect(inker.tags.size).toBe(0); // queued until the engine is built
		inker.boot();
		const bouncer = {
			can: async (action: string) => action === "post.edit",
			cannot: async (action: string) => action !== "post.edit",
		};
		expect(
			await renderTag(inker.tags.get("can"), { bouncer }, "'post.edit'"),
		).toBe("BODY");
		expect(
			await renderTag(inker.tags.get("cannot"), { bouncer }, "'post.edit'"),
		).toBe("");
	});

	it("skips an app with no template engine without importing anything", async () => {
		let imported = false;
		expect(
			await installBouncerTemplateTags(false, async () => {
				imported = true;
				return {};
			}),
		).toBe(false);
		expect(imported).toBe(false);
	});

	it("fails loudly when the engine package has no use() — no silent skip", async () => {
		await expect(
			installBouncerTemplateTags(true, async () => ({ default: {} })),
		).rejects.toMatchObject({ code: "E_WARDEN_TEMPLATE_ENGINE_UNUSABLE" });
	});

	it("fails loudly when the engine it is handed cannot register tags", async () => {
		let plugin: Plugin | undefined;
		await installBouncerTemplateTags(true, async () => ({
			default: {
				use(p: Plugin) {
					plugin = p;
				},
			},
		}));
		expect(() => plugin?.({})).toThrow(/registerTag/);
	});
});
