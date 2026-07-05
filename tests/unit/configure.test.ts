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
