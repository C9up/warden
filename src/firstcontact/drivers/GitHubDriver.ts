/**
 * GitHub OAuth2 driver for FirstContact.
 */

import { Oauth2Driver, str } from "../Oauth2Driver.js";
import type { OAuthUser } from "../types.js";

const EMAILS_URL = "https://api.github.com/user/emails";

/** One entry of `/user/emails`. */
interface GitHubEmail {
	email: string;
	primary: boolean;
	verified: boolean;
}

export class GitHubDriver extends Oauth2Driver {
	protected readonly provider = "GitHub";
	protected readonly authorizeUrl = "https://github.com/login/oauth/authorize";
	protected readonly accessTokenUrl =
		"https://github.com/login/oauth/access_token";
	protected readonly userInfoUrl = "https://api.github.com/user";
	protected readonly defaultScopes = ["read:user", "user:email"] as const;

	/**
	 * An account whose address is private returns `email: null` from `/user`,
	 * which is most accounts. The address then lives behind `/user/emails`,
	 * which also says whether GitHub verified it.
	 */
	protected override async fetchUser(accessToken: string): Promise<OAuthUser> {
		const raw = await this.get(this.userInfoUrl, accessToken);
		const user = this.mapUser(raw);
		if (user.email !== "") return user;

		const found = await this.fetchEmail(accessToken);
		if (found === undefined) return user;
		return {
			...user,
			email: found.email,
			emailVerificationState: found.verified ? "verified" : "unverified",
		};
	}

	/**
	 * The verified primary address, or the best available one. Returns
	 * `undefined` when the token was not granted `user:email` — a sign-in
	 * without an address is still a sign-in.
	 */
	async fetchEmail(accessToken: string): Promise<GitHubEmail | undefined> {
		let entries: unknown[];
		try {
			entries = await this.getList(EMAILS_URL, accessToken);
		} catch {
			return undefined;
		}
		const emails = entries.filter(isGitHubEmail);
		// Primary first, then verified: an unverified primary is still the
		// address the account is known by.
		return (
			emails.find((entry) => entry.primary && entry.verified) ??
			emails.find((entry) => entry.verified) ??
			emails.find((entry) => entry.primary) ??
			emails[0]
		);
	}

	protected mapUser(raw: Record<string, unknown>): OAuthUser {
		return {
			id: String(raw.id ?? ""),
			email: String(raw.email ?? ""),
			// An account with no display name still has a login.
			name: String(raw.name ?? raw.login ?? ""),
			nickName: str(raw, "login"),
			avatarUrl: str(raw, "avatar_url"),
			// `/user` says nothing about the address; `fetchUser` refines this
			// when it has to read `/user/emails`.
			emailVerificationState: "unsupported",
			raw,
		};
	}
}

function isGitHubEmail(value: unknown): value is GitHubEmail {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof Reflect.get(value, "email") === "string"
	);
}
