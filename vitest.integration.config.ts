import { defineConfig } from "vitest/config";

// Integration layer: the suites that need a live Redis. They are excluded from
// the default config because they SKIP without a server, and the CI smoke gate
// requires zero skipped tests (that is how a NAPI binary failing to load gets
// caught). Here they are the only thing that runs, against a real service.
export default defineConfig({
	test: {
		include: ["tests/**/*.integration.test.ts"],
	},
});
