import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// Integration tests need a live Redis and SKIP without one. The CI smoke
		// gate requires zero skipped tests — that is how a NAPI binary failing to
		// load gets caught — so they run in their own job (`test:integration`),
		// against a real Redis service, rather than skipping here.
			// `src/vendor/**` is generated from scripts/vendor/ and identical in every
			// package that carries it, so measuring it here counts the same lines N
			// times and holds this package to a floor for code it cannot change. The
			// behaviour is pinned where it broke: bay's quasar-bridge suite covers the
			// two manager shapes the loader has to accept.
		exclude: ["**/node_modules/**", "**/dist/**", "**/*.integration.test.ts"],
		coverage: {
			provider: "v8",
			include: ["src/**"],
			exclude: ["src/**/*.d.ts", "src/vendor/**"],
			reporter: ["text-summary", "json-summary"],
			thresholds: {
				lines: 79,
				statements: 77,
				branches: 65,
				functions: 76,
			},
		},
	},
});
