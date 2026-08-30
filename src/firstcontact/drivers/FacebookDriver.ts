/**
 * Facebook OAuth2 driver for FirstContact.
 */

import { Oauth2Driver } from "../Oauth2Driver.js";
import type { OAuthUser } from "../types.js";

/** The Graph API returns nothing but the id unless the fields are asked for. */
const USER_FIELDS = [
	"name",
	"first_name",
	"last_name",
	"link",
	"email",
	"picture.width(400).height(400)",
] as const;

export class FacebookDriver extends Oauth2Driver {
	protected readonly provider = "Facebook";
	protected readonly authorizeUrl =
		"https://www.facebook.com/v21.0/dialog/oauth";
	protected readonly accessTokenUrl =
		"https://graph.facebook.com/v21.0/oauth/access_token";
	protected readonly userInfoUrl = "https://graph.facebook.com/v21.0/me";
	protected readonly defaultScopes = ["email"] as const;

	protected override userInfoParams(): Record<string, string> {
		return { fields: USER_FIELDS.join(",") };
	}

	protected mapUser(raw: Record<string, unknown>): OAuthUser {
		return {
			id: String(raw.id ?? ""),
			// The address is absent unless the user granted the `email` scope.
			email: String(raw.email ?? ""),
			name: String(raw.name ?? ""),
			nickName: typeof raw.name === "string" ? raw.name : undefined,
			avatarUrl: pictureUrl(raw),
			emailVerificationState: "unsupported",
			raw,
		};
	}
}

/** The picture arrives nested as `picture.data.url`. */
function pictureUrl(raw: Record<string, unknown>): string | undefined {
	const picture = raw.picture;
	if (typeof picture !== "object" || picture === null) return undefined;
	const data = Reflect.get(picture, "data");
	if (typeof data !== "object" || data === null) return undefined;
	const url = Reflect.get(data, "url");
	return typeof url === "string" && url !== "" ? url : undefined;
}
