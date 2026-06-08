import { randomBytes } from "node:crypto";

interface Codemods {
	addProvider(importPath: string): Promise<void>;
	addEnvVars(vars: Record<string, string>): Promise<void>;
	writeFile(
		filePath: string,
		content: string,
		options?: { force?: boolean },
	): Promise<void>;
}

export async function configure(codemods: Codemods): Promise<void> {
	const jwtSecret = randomBytes(32).toString("hex");
	await codemods.addProvider("@c9up/warden/provider");
	await codemods.addEnvVars({
		JWT_SECRET: jwtSecret,
		JWT_EXPIRY: "3600",
	});
	await codemods.writeFile(
		"config/auth.ts",
		`import { defineConfig } from '@c9up/warden'

export default defineConfig({
  defaultStrategy: 'jwt',
  jwt: {
    secret: process.env.JWT_SECRET ?? '',
    expiresInSeconds: Number(process.env.JWT_EXPIRY ?? '3600'),
    // TODO: wire these to your user model (e.g. via your ORM).
    // The JWT strategy needs both to issue and verify tokens.
    findUser: async (_id) => {
      throw new Error('TODO: implement findUser(id) for the JWT strategy in config/auth.ts')
    },
    verifyCredentials: async (_email, _password) => {
      throw new Error('TODO: implement verifyCredentials(email, password) in config/auth.ts')
    },
  },
})
`,
	);
	// Announce the TODOs on stderr so `ream add @c9up/warden` doesn't end
	// with a quiet success that the user reads as "auth is wired". The
	// generated config/auth.ts ships with `throw new Error('TODO ...')`
	// stubs for findUser + verifyCredentials — login and JWT verify will
	// fail at the first call until the user fills them in. Surfacing the
	// list here means an operator running the installer sees it
	// immediately, not at the first request that hits the auth path.
	process.stderr.write(
		[
			"",
			"[@c9up/warden] config/auth.ts written with TODO stubs:",
			"  - jwt.findUser(id) — wire to your user lookup (ORM)",
			"  - jwt.verifyCredentials(email, password) — wire to your sign-in flow",
			"Both throw at runtime until you implement them — login + JWT verify",
			"will fail with `TODO: implement …` errors otherwise.",
			"",
		].join("\n"),
	);
}
