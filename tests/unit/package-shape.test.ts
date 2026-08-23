/**
 * AC3 — agnostic publish-shape gate (AC-E7/E8, no legacy shims).
 *
 * A static manifest + barrel-surface assertion that fails if the package drifts
 * from "publishable + clean": no `@adonisjs/*` dependency anywhere, every
 * `exports` subpath resolving to a real file with a `publishConfig` mirror under
 * `dist/`, the full authorization surface re-exported from the main barrel, and
 * NO legacy shim symbols / `@deprecated` aliases (AD6 — clean replace).
 *
 * `package.json` is parsed through a typed shape + runtime guard (no `as`).
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import * as warden from "../../src/index.js";

// — Typed manifest shape + runtime guard (no `as`, no `any`) —

interface ExportEntry {
	types: string;
	import: string;
}

interface Manifest {
	dependencies?: Record<string, string>;
	peerDependencies?: Record<string, string>;
	devDependencies?: Record<string, string>;
	description: string;
	exports: Record<string, ExportEntry>;
	publishConfig: { exports: Record<string, ExportEntry> };
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function isStringMap(value: unknown): value is Record<string, string> {
	if (!isRecord(value)) return false;
	for (const key of Object.keys(value)) {
		if (typeof value[key] !== "string") return false;
	}
	return true;
}

function isExportEntry(value: unknown): value is ExportEntry {
	return (
		isRecord(value) &&
		typeof value.import === "string" &&
		typeof value.types === "string"
	);
}

function isExportMap(value: unknown): value is Record<string, ExportEntry> {
	if (!isRecord(value)) return false;
	for (const key of Object.keys(value)) {
		if (!isExportEntry(value[key])) return false;
	}
	return true;
}

function isManifest(value: unknown): value is Manifest {
	if (!isRecord(value)) return false;
	if (typeof value.description !== "string") return false;
	if (!isExportMap(value.exports)) return false;
	if (
		!isRecord(value.publishConfig) ||
		!isExportMap(value.publishConfig.exports)
	)
		return false;
	for (const block of ["dependencies", "peerDependencies", "devDependencies"]) {
		const present = value[block];
		if (present !== undefined && !isStringMap(present)) return false;
	}
	return true;
}

const root = fileURLToPath(new URL("../../", import.meta.url));
const parsed: unknown = JSON.parse(
	readFileSync(join(root, "package.json"), "utf8"),
);
if (!isManifest(parsed)) {
	throw new Error("package.json does not match the expected manifest shape");
}
const manifest: Manifest = parsed;
const barrelSource = readFileSync(join(root, "src/index.ts"), "utf8");

/**
 * Whole-word match against the barrel source. A bare `includes()` is too weak:
 * `Ability` is a substring of `AbilityOptions` and `Scope` of `BouncerContext`,
 * so a substring check stays green even if the bare re-export is deleted. A word
 * boundary pins the actual symbol, not an accidental substring.
 */
function barrelHasSymbol(name: string): boolean {
	return new RegExp(`\\b${name}\\b`).test(barrelSource);
}

/** Runtime-valued authorization exports — asserted defined on the barrel. */
const VALUE_SURFACE = [
	"Bouncer",
	"BasePolicy",
	"AuthorizationResponse",
	"action",
	"allowGuest",
	"getActionMetadata",
	"MemoryRightsStore",
	"RightsResolver",
	"scopeKey",
];

/** Type-only authorization exports — asserted present in the barrel source. */
const TYPE_SURFACE = [
	"PolicyAuthorizer",
	"Ability",
	"AbilityOptions",
	"AuthorizerResponse",
	"BouncerContext",
	"EffectivePermissions",
	"RightsStore",
	"Scope",
];

/** Symbols a clean-replace must never re-introduce (AD6). */
const FORBIDDEN_SHIMS = ["checkPolicy", "PolicyFn", "PolicyContext"];

describe("warden > package shape (AC3 — agnostic + clean)", () => {
	it("declares no @adonisjs/* dependency in any block (AC-E8 zero bouncer dep)", () => {
		const blocks = [
			manifest.dependencies,
			manifest.peerDependencies,
			manifest.devDependencies,
		];
		for (const block of blocks) {
			for (const name of Object.keys(block ?? {})) {
				expect(name.startsWith("@adonisjs/")).toBe(false);
			}
		}
	});

	it("resolves every exports subpath to a real file and mirrors it under dist/", () => {
		const subpaths = Object.keys(manifest.exports);
		expect(subpaths).toContain(".");

		for (const [subpath, entry] of Object.entries(manifest.exports)) {
			expect(existsSync(join(root, entry.import))).toBe(true);
			expect(existsSync(join(root, entry.types))).toBe(true);

			const published = manifest.publishConfig.exports[subpath];
			expect(published).toBeDefined();
			expect(published?.import.startsWith("./dist/")).toBe(true);
			expect(published?.types.startsWith("./dist/")).toBe(true);
		}

		// publishConfig mirrors exactly the same subpaths — no extra, none missing.
		expect(Object.keys(manifest.publishConfig.exports).sort()).toEqual(
			subpaths.sort(),
		);
	});

	it("re-exports the full authorization value surface from the main barrel", () => {
		for (const name of VALUE_SURFACE) {
			expect(Reflect.get(warden, name)).toBeDefined();
		}
	});

	it("re-exports the full authorization type surface from the main barrel", () => {
		for (const name of TYPE_SURFACE) {
			expect(barrelHasSymbol(name)).toBe(true);
		}
	});

	it("exposes no legacy shim symbol and no @deprecated alias (AD6 clean replace)", () => {
		for (const shim of FORBIDDEN_SHIMS) {
			expect(Reflect.get(warden, shim)).toBeUndefined();
			expect(barrelHasSymbol(shim)).toBe(false);
		}
		expect(barrelSource.includes("@deprecated")).toBe(false);
	});
});
