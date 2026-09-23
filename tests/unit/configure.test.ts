import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { configure } from "../../src/configure.js";

interface RecordedFile {
	path: string;
	content: string;
	options?: { force?: boolean };
}

interface FakeCodemodsState {
	providers: string[];
	envVars: Record<string, string>;
	files: RecordedFile[];
}

/**
 * Read a stub the way `codemods.makeUsingStub` does.
 *
 * The real file, not a fixture: a test that stubbed this out would pass with
 * a stub that does not exist.
 */
function renderStub(
	stubsRoot: string,
	stubPath: string,
	state: Record<string, string | number | boolean>,
): { to: string; body: string } {
	const raw = readFileSync(resolve(stubsRoot, stubPath), "utf8");
	const [, front = "", body = ""] = raw.split(/^---\r?\n/m, 3);
	const declared = /^to:\s*(.+)$/m.exec(front)?.[1]?.trim() ?? "";
	const render = (text: string): string =>
		text.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (match, key: string) =>
			state[key] === undefined ? match : String(state[key]),
		);
	return { to: render(declared), body: render(body) };
}

function createFakeCodemods(): {
	state: FakeCodemodsState;
	codemods: {
		addProvider: (importPath: string) => Promise<void>;
		addEnvVars: (vars: Record<string, string>) => Promise<void>;
		writeFile: (
			path: string,
			content: string,
			options?: { force?: boolean },
		) => Promise<void>;
		makeUsingStub: (
			stubsRoot: string,
			stubPath: string,
			state?: Record<string, string | number | boolean>,
			options?: { force?: boolean },
		) => Promise<{ path: string; contents: string }>;
	};
} {
	const state: FakeCodemodsState = {
		providers: [],
		envVars: {},
		files: [],
	};
	return {
		state,
		codemods: {
			async addProvider(importPath) {
				state.providers.push(importPath);
			},
			async addEnvVars(vars) {
				Object.assign(state.envVars, vars);
			},
			async makeUsingStub(
				stubsRoot: string,
				stubPath: string,
				state: Record<string, string | number | boolean> = {},
			) {
				const { to, body } = renderStub(stubsRoot, stubPath, state);
				await this.writeFile(to, body);
				return { path: to, contents: body };
			},
			async writeFile(path, content, options) {
				state.files.push({ path, content, options });
			},
		},
	};
}

describe("warden > configure", () => {
	it("registers the provider, env vars and config file", async () => {
		const { state, codemods } = createFakeCodemods();
		await configure(codemods);

		expect(state.providers).toEqual(["@c9up/warden/provider"]);
		expect(state.envVars.JWT_EXPIRY).toBe("3600");
		// 32 random bytes hex-encoded -> 64 hex chars.
		expect(state.envVars.JWT_SECRET).toMatch(/^[0-9a-f]{64}$/);
		expect(state.files).toHaveLength(1);
		expect(state.files[0]?.path).toBe("config/auth.ts");
		expect(state.files[0]?.content).toContain("@c9up/warden");
		expect(state.files[0]?.content).toContain("default: 'jwt'");
		expect(state.files[0]?.content).toContain("jwtGuard(");
		expect(state.files[0]?.content).toContain("process.env.JWT_SECRET");
	});

	it("generates a fresh JWT_SECRET each invocation", async () => {
		const a = createFakeCodemods();
		const b = createFakeCodemods();
		await configure(a.codemods);
		await configure(b.codemods);
		expect(a.state.envVars.JWT_SECRET).not.toBe(b.state.envVars.JWT_SECRET);
	});
});
