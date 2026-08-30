/**
 * Discord OAuth2 driver for FirstContact.
 */

import { Oauth2Driver } from "../Oauth2Driver.js";
import type { OAuthUser } from "../types.js";

export class DiscordDriver extends Oauth2Driver {
	protected readonly provider = "Discord";
	protected readonly authorizeUrl = "https://discord.com/oauth2/authorize";
	protected readonly accessTokenUrl = "https://discord.com/api/oauth2/token";
	protected readonly userInfoUrl = "https://discord.com/api/users/@me";
	/** `email` is what makes the address present at all; `identify` is the rest. */
	protected readonly defaultScopes = ["identify", "email"] as const;

	protected mapUser(raw: Record<string, unknown>): OAuthUser {
		const id = String(raw.id ?? "");
		return {
			id,
			email: String(raw.email ?? ""),
			name: String(raw.global_name ?? raw.username ?? ""),
			nickName: typeof raw.username === "string" ? raw.username : undefined,
			avatarUrl: avatarUrl(id, raw),
			// Discord reports it only when the `email` scope was granted.
			emailVerificationState:
				"verified" in raw
					? raw.verified === true
						? "verified"
						: "unverified"
					: "unsupported",
			raw,
		};
	}
}

/**
 * Discord serves avatars from a CDN path built from the id and the hash, and
 * animated ones only as `.gif`. An account with no avatar has a default one
 * derived from its id.
 */
function avatarUrl(id: string, raw: Record<string, unknown>): string {
	const hash = raw.avatar;
	if (typeof hash !== "string" || hash === "") {
		// Post-migration accounts (no discriminator) index the defaults by id.
		const index = (BigInt(id || "0") >> 22n) % 6n;
		return `https://cdn.discordapp.com/embed/avatars/${index}.png`;
	}
	const extension = hash.startsWith("a_") ? "gif" : "png";
	return `https://cdn.discordapp.com/avatars/${id}/${hash}.${extension}`;
}
