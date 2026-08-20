/**
 * @module @c9up/warden
 * @description Warden — Authentication & authorization for the Ream framework
 * @implements FR48, FR49, FR50, FR51, FR52, FR53
 */

export type { AuthAttempt, ExtractedCredentials } from "./Authenticator.js";
export {
	API_KEY_GUARD_NAMES,
	Authenticator,
	extractCredentials,
	GuardAccessor,
} from "./Authenticator.js";
export type {
	AuthConfig,
	AuthResult,
	AuthStrategy,
	UserPayload,
} from "./AuthManager.js";
export { AuthManager } from "./AuthManager.js";
export type { AuthRateLimiterConfig } from "./AuthRateLimiter.js";
export { AuthRateLimiter } from "./AuthRateLimiter.js";
export { AbilitiesBuilder } from "./bouncer/AbilitiesBuilder.js";
export { AuthorizationResponse } from "./bouncer/AuthorizationResponse.js";
export { BasePolicy } from "./bouncer/BasePolicy.js";
export { Bouncer } from "./bouncer/Bouncer.js";
export {
	action,
	allowGuest,
	getActionMetadata,
} from "./bouncer/decorators.js";
export type { PolicyAuthorizer } from "./bouncer/PolicyAuthorizer.js";
export type {
	Ability,
	AbilityOptions,
	AuthorizerResponse,
	BouncerContext,
	BouncerEmitter,
	PolicyContainerResolver,
} from "./bouncer/types.js";
export type { GuardFactory, WardenConfig } from "./config.js";
export {
	apiKeyGuard,
	defineConfig,
	jwtGuard,
	sessionGuard,
} from "./config.js";
export { configure } from "./configure.js";
export {
	E_INVALID_CREDENTIALS,
	E_UNAUTHORIZED_ACCESS,
	WardenError,
} from "./errors.js";
export { GitHubDriver } from "./firstcontact/drivers/GitHubDriver.js";
export { GoogleDriver } from "./firstcontact/drivers/GoogleDriver.js";
export { FirstContactManager } from "./firstcontact/FirstContactManager.js";
export type {
	FirstContactDriver,
	OAuthConfig,
	OAuthToken,
	OAuthUser,
} from "./firstcontact/types.js";
export {
	Guard,
	getGuardMetadata,
	getPermissionMetadata,
	getRequireMfaMetadata,
	getRoleMetadata,
	Permission,
	RequireMfa,
	Role,
} from "./Guard.js";
export type {
	BackupCodesConfig,
	BackupCodesResult,
	BackupCodeVerification,
} from "./mfa/BackupCodesProvider.js";
export { BackupCodesProvider } from "./mfa/BackupCodesProvider.js";
export type {
	MfaFactor,
	MfaFactorKind,
	MfaFactorStore,
	MfaFactorSummary,
	MfaManagerConfig,
} from "./mfa/MfaManager.js";
export { MemoryMfaFactorStore, MfaManager } from "./mfa/MfaManager.js";
export type {
	OtpChallenge,
	OtpChallengeStore,
	OtpConfig,
	OtpDeliveryChannel,
	OtpFailureReason,
	OtpStartResult,
	OtpVerification,
} from "./mfa/OtpProvider.js";
export { MemoryOtpChallengeStore, OtpProvider } from "./mfa/OtpProvider.js";
export type {
	TotpAlgorithm,
	TotpConfig,
	TotpEnrollment,
} from "./mfa/TotpProvider.js";
export { TotpProvider } from "./mfa/TotpProvider.js";
export type {
	AuthenticationOptionsJSON,
	AuthenticationResponseJSON,
	RegistrationOptionsJSON,
	RegistrationResponseJSON,
	StoredPasskey,
	WebauthnChallengeStore,
	WebauthnConfig,
	WebauthnCredentialStore,
	WebauthnUser,
} from "./mfa/WebauthnProvider.js";
export {
	MemoryWebauthnChallengeStore,
	MemoryWebauthnCredentialStore,
	WebauthnProvider,
} from "./mfa/WebauthnProvider.js";
export { quasarConnection } from "./quasar.js";
export type {
	RedisBlacklistConfig,
	RedisLikeClient,
} from "./RedisBlacklistDriver.js";
export { RedisBlacklistDriver } from "./RedisBlacklistDriver.js";
export type {
	RefreshTokenDriver,
	StoredRefreshToken,
} from "./RefreshTokenStore.js";
export {
	generateRefreshToken,
	MemoryRefreshTokenDriver,
} from "./RefreshTokenStore.js";
export type {
	BlacklistDegradeEvent,
	ResilientBlacklistConfig,
} from "./ResilientBlacklistDriver.js";
export { ResilientBlacklistDriver } from "./ResilientBlacklistDriver.js";
export { MemoryRightsStore } from "./rights/MemoryRightsStore.js";
export { RightsResolver } from "./rights/RightsResolver.js";
export type {
	EffectivePermissions,
	RightsStore,
	Scope,
} from "./rights/types.js";
export { scopeKey } from "./rights/types.js";
export type { ApiKeyConfig } from "./strategies/ApiKeyStrategy.js";
export { ApiKeyStrategy } from "./strategies/ApiKeyStrategy.js";
export type { JwtClaims, JwtStrategyConfig } from "./strategies/JwtStrategy.js";
export { generateJwtSecret, JwtStrategy } from "./strategies/JwtStrategy.js";
export type {
	SessionStore,
	SessionStrategyConfig,
} from "./strategies/SessionStrategy.js";
export { SessionStrategy } from "./strategies/SessionStrategy.js";
export type { BlacklistDriver } from "./TokenBlacklist.js";
export { MemoryBlacklistDriver, TokenBlacklist } from "./TokenBlacklist.js";
