import { randomBytes } from "node:crypto";
import { stubsRoot } from "./stubs.js";

interface Codemods {
	addProvider(importPath: string): Promise<void>;
	addEnvVars(vars: Record<string, string>): Promise<void>;
	writeFile(
		filePath: string,
		content: string,
		options?: { force?: boolean },
	): Promise<void>;
	makeUsingStub(
		stubsRoot: string,
		stubPath: string,
		state?: Record<string, string | number | boolean>,
		options?: { force?: boolean },
	): Promise<{ path: string; contents: string }>;
}

export async function configure(codemods: Codemods): Promise<void> {
	const jwtSecret = randomBytes(32).toString("hex");
	await codemods.addProvider("@c9up/warden/provider");
	await codemods.addEnvVars({
		JWT_SECRET: jwtSecret,
		JWT_EXPIRY: "3600",
	});
	await codemods.makeUsingStub(stubsRoot, "config/auth.stub");
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
