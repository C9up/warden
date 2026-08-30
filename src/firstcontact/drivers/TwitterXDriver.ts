/**
 * X (Twitter) OAuth2 driver for FirstContact.
 *
 * X requires PKCE, so this driver refuses to build a redirect without a code
 * verifier. Mint one with `createCodeVerifier()`, store it beside the state,
 * and hand it back to `callback()`.
 */

import { Oauth2Driver } from "../Oauth2Driver.js";
import type { OAuthUser } from "../types.js";

export class TwitterXDriver extends Oauth2Driver {
	protected readonly provider = "X";
	protected readonly authorizeUrl = "https://x.com/i/oauth2/authorize";
	protected readonly accessTokenUrl = "https://api.x.com/2/oauth2/token";
	protected readonly userInfoUrl = "https://api.x.com/2/users/me";
	protected readonly defaultScopes = [
		"tweet.read",
		"users.read",
		"users.email",
	] as const;
	protected override readonly requiresPkce = true;
	/** X accepts the client credentials only as HTTP Basic. */
	protected override readonly tokenAuth = "basic" as const;

	protected override userInfoParams(): Record<string, string> {
		// Neither the picture nor the address is returned unless asked for.
		return { "user.fields": "profile_image_url,confirmed_email" };
	}

	protected override mapUser(raw: Record<string, unknown>): OAuthUser {
		// The profile arrives wrapped: `{ data: { ... } }`.
		const data =
			typeof raw.data === "object" && raw.data !== null
				? (raw.data as Record<string, unknown>)
				: raw;
		return {
			id: String(data.id ?? ""),
			email: String(data.confirmed_email ?? ""),
			name: String(data.name ?? data.username ?? ""),
			nickName: typeof data.username === "string" ? data.username : undefined,
			avatarUrl:
				typeof data.profile_image_url === "string" &&
				data.profile_image_url !== ""
					? data.profile_image_url
					: undefined,
			// The field is named `confirmed_email`, but X publishes no separate
			// verification flag, so nothing here can be claimed.
			emailVerificationState: "unsupported",
			raw,
		};
	}
}
