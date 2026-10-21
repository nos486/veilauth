// Generated from spec/api.openapi.yaml by packages/shared/scripts/gen-kotlin.mjs. Do not edit.
// Regenerate with `pnpm --filter @zk2fa/shared kotlin`; CI runs `kotlin:check`.
@file:Suppress("ktlint")

package app.zk2fa.core.api

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

public object ApiPaths {
    public const val CONFIG: String = "/api/v1/config"
    public const val TIME: String = "/api/v1/time"
    public const val AUTH_PRELOGIN: String = "/api/v1/auth/prelogin"
    public const val AUTH_REGISTER: String = "/api/v1/auth/register"
    public const val AUTH_LOGIN: String = "/api/v1/auth/login"
    public const val AUTH_REFRESH: String = "/api/v1/auth/refresh"
    public const val AUTH_LOGOUT: String = "/api/v1/auth/logout"
    public const val AUTH_CHANGE_PASSWORD: String = "/api/v1/auth/change-password"
    public const val AUTH_RECOVER_START: String = "/api/v1/auth/recover/start"
    public const val AUTH_RECOVER: String = "/api/v1/auth/recover"
    public const val SYNC: String = "/api/v1/sync"
    public const val SYNC_PUSH: String = "/api/v1/sync/push"
    public const val DEVICES: String = "/api/v1/devices"
    public const val DEVICES_BY_ID: String = "/api/v1/devices/{id}"
    public const val ACCOUNT: String = "/api/v1/account"
}

@Serializable
public enum class ApiErrorCode {
    @SerialName("BAD_REQUEST")
    BAD_REQUEST,
    @SerialName("PAYLOAD_TOO_LARGE")
    PAYLOAD_TOO_LARGE,
    @SerialName("UNAUTHORIZED")
    UNAUTHORIZED,
    @SerialName("INVALID_CREDENTIALS")
    INVALID_CREDENTIALS,
    @SerialName("TOKEN_EXPIRED")
    TOKEN_EXPIRED,
    @SerialName("SESSION_REVOKED")
    SESSION_REVOKED,
    @SerialName("REFRESH_REUSED")
    REFRESH_REUSED,
    @SerialName("FORBIDDEN")
    FORBIDDEN,
    @SerialName("NOT_FOUND")
    NOT_FOUND,
    @SerialName("EMAIL_TAKEN")
    EMAIL_TAKEN,
    @SerialName("ID_TAKEN")
    ID_TAKEN,
    @SerialName("KDF_PARAMS_REJECTED")
    KDF_PARAMS_REJECTED,
    @SerialName("RATE_LIMITED")
    RATE_LIMITED,
    @SerialName("ACCOUNT_LOCKED")
    ACCOUNT_LOCKED,
    @SerialName("TURNSTILE_REQUIRED")
    TURNSTILE_REQUIRED,
    @SerialName("TURNSTILE_FAILED")
    TURNSTILE_FAILED,
    @SerialName("VAULT_LIMIT")
    VAULT_LIMIT,
    @SerialName("SYNC_RETRY")
    SYNC_RETRY,
    @SerialName("INTERNAL")
    INTERNAL,
}

@Serializable
public data class ApiError(
    val code: ApiErrorCode,
    val message: String,
)

@Serializable
public data class KdfParams(
    val m: Long,
    val t: Long,
    val p: Long,
)

@Serializable
public data class Kdf(
    val alg: String,
    val version: Long,
    val params: KdfParams,
    val salt: String,
)

@Serializable
public data class ChangePasswordRequest(
    val authKey: String,
    val newKdf: Kdf,
    val newAuthKey: String,
    val newWrappedVaultKey: String,
)

@Serializable
public data class ConfigResponseKdf(
    val alg: String,
    val version: Long,
    val params: KdfParams,
)

@Serializable
public data class ConfigResponseLimits(
    val maxItemsPerUser: Long,
    val maxBlobChars: Long,
    val maxChangesPerPush: Long,
)

@Serializable
public data class ConfigResponse(
    val turnstileSiteKey: String?,
    val kdf: ConfigResponseKdf,
    val limits: ConfigResponseLimits,
)

@Serializable
public data class DeleteAccountRequest(
    val authKey: String,
)

@Serializable
public enum class Platform {
    @SerialName("web")
    WEB,
    @SerialName("android")
    ANDROID,
}

@Serializable
public data class Device(
    val id: String,
    val platform: Platform,
    val nameEnc: String?,
    val createdAt: Long,
    val lastSeenAt: Long,
    val current: Boolean,
)

@Serializable
public data class DeviceInfo(
    val id: String,
    val platform: Platform,
    val nameEnc: String?,
)

@Serializable
public data class DevicesResponse(
    val devices: List<Device>,
)

@Serializable
public enum class ItemKind {
    @SerialName("token")
    TOKEN,
    @SerialName("folder")
    FOLDER,
    @SerialName("settings")
    SETTINGS,
}

@Serializable
public data class LoginRequest(
    val email: String,
    val authKey: String,
    val device: DeviceInfo,
    val turnstileToken: String? = null,
)

@Serializable
public data class PreloginRequest(
    val email: String,
)

@Serializable
public data class PreloginResponse(
    val kdf: Kdf,
)

@Serializable
public data class PushChange(
    val id: String,
    val kind: ItemKind,
    val blob: String?,
    val baseRevision: Long,
)

@Serializable
public enum class PushConflictReason {
    @SerialName("revision_mismatch")
    REVISION_MISMATCH,
    @SerialName("kind_mismatch")
    KIND_MISMATCH,
}

@Serializable
public data class VaultItem(
    val id: String,
    val kind: ItemKind,
    val blob: String?,
    val revision: Long,
    val deleted: Boolean,
    val updatedAt: Long,
)

@Serializable
public data class PushConflict(
    val id: String,
    val reason: PushConflictReason,
    val server: VaultItem?,
)

@Serializable
public data class PushRequest(
    val changes: List<PushChange>,
)

@Serializable
public data class PushResponseAppliedItem(
    val id: String,
    val revision: Long,
)

@Serializable
public data class PushResponse(
    val revision: Long,
    val applied: List<PushResponseAppliedItem>,
    val conflicts: List<PushConflict>,
)

@Serializable
public data class RecoveryData(
    val authKey: String,
    val wrappedVaultKey: String,
)

@Serializable
public data class RecoverRequest(
    val email: String,
    val recoveryAuthKey: String,
    val newKdf: Kdf,
    val newAuthKey: String,
    val newWrappedVaultKey: String,
    val newRecovery: RecoveryData,
    val device: DeviceInfo,
)

@Serializable
public data class RecoverStartRequest(
    val email: String,
    val recoveryAuthKey: String,
)

@Serializable
public data class RecoverStartResponse(
    val userId: String,
    val recoveryWrappedVaultKey: String,
)

@Serializable
public data class RefreshRequest(
    val refreshToken: String,
)

@Serializable
public data class RefreshResponse(
    val accessToken: String,
    val accessTokenExpiresAt: Long,
    val refreshToken: String,
)

@Serializable
public data class RegisterRequest(
    val userId: String,
    val email: String,
    val kdf: Kdf,
    val authKey: String,
    val wrappedVaultKey: String,
    val recovery: RecoveryData,
    val device: DeviceInfo,
    val turnstileToken: String? = null,
)

@Serializable
public data class SessionResponse(
    val userId: String,
    val deviceId: String,
    val accessToken: String,
    val accessTokenExpiresAt: Long,
    val refreshToken: String,
    val wrappedVaultKey: String,
    val kdf: Kdf,
    val vaultRevision: Long,
    val kdfUpgradeRequired: Boolean,
)

@Serializable
public data class SyncQuery(
    val since: Long? = null,
)

@Serializable
public data class SyncResponse(
    val revision: Long,
    val full: Boolean,
    val items: List<VaultItem>,
)

@Serializable
public data class TimeResponse(
    val now: Long,
)
