package app.zk2fa.core.vault

import app.zk2fa.core.api.ApiClient
import app.zk2fa.core.api.DeviceInfo
import app.zk2fa.core.api.Kdf
import app.zk2fa.core.api.LoginRequest
import app.zk2fa.core.api.Platform
import app.zk2fa.core.api.SessionResponse
import app.zk2fa.core.crypto.CryptoErrorCode
import app.zk2fa.core.crypto.CryptoException
import app.zk2fa.core.crypto.KdfParams
import app.zk2fa.core.crypto.deriveLoginKeys
import app.zk2fa.core.crypto.fromBase64Url
import app.zk2fa.core.crypto.toBase64Url
import app.zk2fa.core.crypto.unwrapVaultKey
import app.zk2fa.core.crypto.validateKdfParams
import app.zk2fa.core.crypto.wipe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** What the device keeps about the signed-in account (no secrets except the wrapped vault key). */
public data class StoredAccount(
    val userId: String,
    val deviceId: String,
    val email: String,
    val kdf: Kdf,
    val wrappedVaultKey: String,
)

/** Validated (alg, params, salt) from a server [Kdf]; a malformed or weak setting is KDF_PARAMS_REJECTED. */
public fun Kdf.validated(): Pair<KdfParams, ByteArray> {
    val salt =
        try {
            fromBase64Url(salt)
        } catch (_: CryptoException) {
            throw CryptoException(CryptoErrorCode.KDF_PARAMS_REJECTED)
        }
    val json = JsonObject(mapOf("m" to JsonPrimitive(params.m), "t" to JsonPrimitive(params.t), "p" to JsonPrimitive(params.p)))
    return validateKdfParams(alg, json, salt) to salt
}

/** Password → vault key for an account cached on this device. Wrong password = DECRYPT_FAILED. */
public suspend fun unlockWithPassword(
    account: StoredAccount,
    password: String,
): ByteArray =
    withContext(Dispatchers.Default) {
        val (params, salt) = account.kdf.validated()
        val keys = deriveLoginKeys(password, salt, params)
        wipe(keys.authKey)
        unwrapVaultKey(keys.kek, account.wrappedVaultKey, account.userId)
    }

public class LoginResult(
    public val account: StoredAccount,
    public val session: SessionResponse,
    /** raw vault key; the caller wipes it after building a [VaultKey] */
    public val vaultKey: ByteArray,
)

/**
 * Online log-in (spec/crypto.md §4): prelogin → KDF policy check → Argon2id → HKDF → login →
 * unwrap. A new device id is registered on every log-in (D-021). The server sees the authKey
 * only, never the password or the KEK.
 */
public suspend fun logIn(
    api: ApiClient,
    email: String,
    password: String,
    deviceId: String = uuidV7(),
): LoginResult {
    val normalized = email.trim()
    val pre = api.prelogin(normalized)
    val (params, salt) = pre.kdf.validated()
    val keys = withContext(Dispatchers.Default) { deriveLoginKeys(password, salt, params) }
    val session =
        try {
            api.login(LoginRequest(normalized, toBase64Url(keys.authKey), DeviceInfo(deviceId, Platform.ANDROID, nameEnc = null)))
        } finally {
            wipe(keys.authKey)
        }
    val vaultKey = unwrapVaultKey(keys.kek, session.wrappedVaultKey, session.userId)
    return LoginResult(StoredAccount(session.userId, session.deviceId, normalized, session.kdf, session.wrappedVaultKey), session, vaultKey)
}
