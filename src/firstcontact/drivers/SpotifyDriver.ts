/**
 * Spotify OAuth2 driver for FirstContact.
 */

import { Oauth2Driver } from "../Oauth2Driver.js";
import type { OAuthUser } from "../types.js";

export class SpotifyDriver extends Oauth2Driver {
	protected readonly provider = "Spotify";
	protected readonly authorizeUrl = "https://accounts.spotify.com/authorize";
	protected readonly accessTokenUrl = "https://accounts.spotify.com/api/token";
	protected readonly userInfoUrl = "https://api.spotify.com/v1/me";
	protected readonly defaultScopes = ["user-read-email"] as const;
	/** Spotify wants the client credentials as HTTP Basic on the token request. */
	protected override readonly tokenAuth = "basic" as const;

	protected mapUser(raw: Record<string, unknown>): OAuthUser {
		return {
			id: String(raw.id ?? ""),
			email: String(raw.email ?? ""),
			name: String(raw.display_name ?? ""),
			nickName:
				typeof raw.display_name === "string" ? raw.display_name : undefined,
			avatarUrl: firstImage(raw),
			// Spotify says nothing about the address it returns.
			emailVerificationState: "unsupported",
			raw,
		};
	}
}

/** Spotify returns a list of images; the first is the one to show. */
function firstImage(raw: Record<string, unknown>): string | undefined {
	const images = raw.images;
	if (!Array.isArray(images) || images.length === 0) return undefined;
	const url = Reflect.get(Object(images[0]), "url");
	return typeof url === "string" && url !== "" ? url : undefined;
}
