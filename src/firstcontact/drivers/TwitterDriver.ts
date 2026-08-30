/**
 * X (Twitter) OAuth1 driver for FirstContact.
 *
 * The older of X's two flows. `TwitterXDriver` is the OAuth2 one, and is what
 * a new application wants; this one exists for an application already built
 * on OAuth1 tokens, and it is also the only flow that returns the address
 * through `verify_credentials`.
 */

import { Oauth1Driver } from "../Oauth1Driver.js";
import type { OAuthUser } from "../types.js";

export class TwitterDriver extends Oauth1Driver {
	protected readonly provider = "X";
	protected readonly requestTokenUrl =
		"https://api.twitter.com/oauth/request_token";
	/** `authenticate`, not `authorize`: a returning user is not asked twice. */
	protected readonly authorizeUrl =
		"https://api.twitter.com/oauth/authenticate";
	protected readonly accessTokenUrl =
		"https://api.twitter.com/oauth/access_token";
	protected readonly userInfoUrl =
		"https://api.twitter.com/1.1/account/verify_credentials.json";

	protected override userInfoParams(): Record<string, string> {
		// The address is omitted unless asked for, and only reaches an
		// application whose X app was granted it.
		return { include_email: "true" };
	}

	protected mapUser(raw: Record<string, unknown>): OAuthUser {
		return {
			// `id_str`, never `id`: the numeric form loses precision past 2^53.
			id: String(raw.id_str ?? ""),
			email: String(raw.email ?? ""),
			name: String(raw.name ?? raw.screen_name ?? ""),
			nickName:
				typeof raw.screen_name === "string" ? raw.screen_name : undefined,
			avatarUrl: fullSizeAvatar(raw),
			// X vouches for nothing about the address it returns.
			emailVerificationState: "unsupported",
			raw,
		};
	}
}

/**
 * The profile carries the 48px thumbnail. The full-size original is the same
 * URL with the `_normal` suffix removed.
 */
function fullSizeAvatar(raw: Record<string, unknown>): string | undefined {
	const url = raw.profile_image_url_https;
	if (typeof url !== "string" || url === "") return undefined;
	return url.replace(/_normal(\.[a-z]+)$/i, "$1");
}
