/**
 * LinkedIn OAuth2 driver for FirstContact — the member API.
 *
 * For an application whose LinkedIn app holds `r_liteprofile` /
 * `r_emailaddress`. It needs two calls: the profile carries no address, and
 * the address endpoint carries no profile.
 *
 * LinkedIn issues new applications OpenID Connect instead — that is
 * `LinkedInOpenidConnectDriver`.
 */

import { Oauth2Driver } from "../Oauth2Driver.js";
import type { OAuthUser } from "../types.js";

const EMAIL_URL = "https://api.linkedin.com/v2/emailAddress";
const PROFILE_PROJECTION =
	"(id,localizedFirstName,localizedLastName,vanityName,profilePicture(displayImage~:playableStreams))";

export class LinkedInDriver extends Oauth2Driver {
	protected readonly provider = "LinkedIn";
	protected readonly authorizeUrl =
		"https://www.linkedin.com/oauth/v2/authorization";
	protected readonly accessTokenUrl =
		"https://www.linkedin.com/oauth/v2/accessToken";
	protected readonly userInfoUrl = "https://api.linkedin.com/v2/me";
	protected readonly defaultScopes = [
		"r_liteprofile",
		"r_emailaddress",
	] as const;

	protected override userInfoParams(): Record<string, string> {
		return { projection: PROFILE_PROJECTION };
	}

	protected override async fetchUser(accessToken: string): Promise<OAuthUser> {
		const raw = await this.get(this.userInfoUrl, accessToken, {
			...this.userInfoParams(),
		});
		const email = await this.fetchEmail(accessToken);
		return { ...this.mapUser(raw), email };
	}

	/**
	 * The address lives behind its own endpoint, and only with the
	 * `r_emailaddress` scope — without it the response has no elements, which is
	 * reported here rather than surfacing as an empty address downstream.
	 */
	async fetchEmail(accessToken: string): Promise<string> {
		const body = await this.get(EMAIL_URL, accessToken, {
			q: "members",
			projection: "(elements*(primary,type,handle~))",
		});
		const elements = Array.isArray(body.elements) ? body.elements : [];
		for (const element of elements) {
			if (typeof element !== "object" || element === null) continue;
			if (Reflect.get(element, "type") !== "EMAIL") continue;
			const handle = Reflect.get(element, "handle~");
			if (typeof handle !== "object" || handle === null) continue;
			const address = Reflect.get(handle, "emailAddress");
			if (typeof address === "string" && address !== "") return address;
		}
		throw new Error(
			"LinkedIn returned no email address — the application needs the 'r_emailaddress' scope.",
		);
	}

	protected mapUser(raw: Record<string, unknown>): OAuthUser {
		const first = String(raw.localizedFirstName ?? "");
		const last = String(raw.localizedLastName ?? "");
		return {
			id: String(raw.id ?? ""),
			email: "",
			name: [first, last].filter(Boolean).join(" "),
			nickName:
				typeof raw.vanityName === "string" && raw.vanityName !== ""
					? raw.vanityName
					: [first, last].filter(Boolean).join(" "),
			avatarUrl: pictureUrl(raw),
			// The member API vouches for nothing about the address.
			emailVerificationState: "unsupported",
			raw,
		};
	}
}

/**
 * The picture arrives as a list of renditions, largest last. Nothing about
 * the shape is guaranteed, so every step is checked.
 */
function pictureUrl(raw: Record<string, unknown>): string | undefined {
	const picture = raw.profilePicture;
	if (typeof picture !== "object" || picture === null) return undefined;
	const display = Reflect.get(picture, "displayImage~");
	if (typeof display !== "object" || display === null) return undefined;
	const elements = Reflect.get(display, "elements");
	if (!Array.isArray(elements) || elements.length === 0) return undefined;
	const identifiers = Reflect.get(Object(elements[0]), "identifiers");
	if (!Array.isArray(identifiers) || identifiers.length === 0) return undefined;
	const identifier = Reflect.get(Object(identifiers[0]), "identifier");
	return typeof identifier === "string" && identifier !== ""
		? identifier
		: undefined;
}
