package app.zk2fa.data

import android.content.Context
import android.util.Base64
import app.zk2fa.core.api.ApiJson
import app.zk2fa.core.api.Kdf
import app.zk2fa.core.api.TokenStore
import app.zk2fa.core.vault.StoredAccount
import app.zk2fa.security.Keystore
import app.zk2fa.security.Sealed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.GeneralSecurityException

/**
 * The signed-in account. Nothing here is plaintext secret: the wrapped vault key needs the
 * master password, the refresh token is sealed with a Keystore key, and the biometric copy of
 * the vault key is sealed with a key that needs a fingerprint/face for every use.
 */
class AccountStore(
    context: Context,
) : TokenStore {
    private val prefs = context.getSharedPreferences("account", Context.MODE_PRIVATE)

    fun load(): StoredAccount? {
        val userId = prefs.getString(USER_ID, null) ?: return null
        val kdfJson = prefs.getString(KDF, null) ?: return null
        return StoredAccount(
            userId = userId,
            deviceId = prefs.getString(DEVICE_ID, null) ?: return null,
            email = prefs.getString(EMAIL, null) ?: return null,
            kdf = ApiJson.decodeFromString(Kdf.serializer(), kdfJson),
            wrappedVaultKey = prefs.getString(WRAPPED, null) ?: return null,
        )
    }

    fun save(account: StoredAccount) {
        prefs
            .edit()
            .putString(USER_ID, account.userId)
            .putString(DEVICE_ID, account.deviceId)
            .putString(EMAIL, account.email)
            .putString(KDF, ApiJson.encodeToString(Kdf.serializer(), account.kdf))
            .putString(WRAPPED, account.wrappedVaultKey)
            .apply()
    }

    /** Last e-mail, kept after a sign-out so the log-in form is pre-filled. */
    fun lastEmail(): String = prefs.getString(EMAIL, null).orEmpty()

    fun hasRefreshToken(): Boolean = prefs.contains(REFRESH_CT)

    override suspend fun loadRefreshToken(): String? =
        withContext(Dispatchers.IO) {
            val sealed = sealed(REFRESH_IV, REFRESH_CT) ?: return@withContext null
            try {
                String(Keystore.openSession(sealed), Charsets.UTF_8)
            } catch (_: GeneralSecurityException) {
                // The Keystore key is gone (e.g. device restored): the session cannot continue.
                clearRefreshToken()
                null
            }
        }

    override suspend fun saveRefreshToken(token: String) {
        withContext(Dispatchers.IO) {
            val sealed = Keystore.sealSession(token.toByteArray(Charsets.UTF_8))
            putSealed(REFRESH_IV, REFRESH_CT, sealed, commit = true)
        }
    }

    fun clearRefreshToken() {
        prefs.edit().remove(REFRESH_IV).remove(REFRESH_CT).apply()
    }

    fun biometricVaultKey(): Sealed? = sealed(BIO_IV, BIO_CT)

    fun saveBiometricVaultKey(sealed: Sealed) = putSealed(BIO_IV, BIO_CT, sealed, commit = false)

    fun clearBiometricVaultKey() {
        prefs.edit().remove(BIO_IV).remove(BIO_CT).apply()
        Keystore.deleteBiometricKey()
    }

    /** Sign-out: forget everything but the e-mail. */
    fun clear() {
        val email = lastEmail()
        prefs.edit().clear().putString(EMAIL, email).apply()
        Keystore.deleteBiometricKey()
    }

    private fun sealed(
        ivKey: String,
        ctKey: String,
    ): Sealed? {
        val iv = prefs.getString(ivKey, null) ?: return null
        val ct = prefs.getString(ctKey, null) ?: return null
        return Sealed(Base64.decode(iv, Base64.NO_WRAP), Base64.decode(ct, Base64.NO_WRAP))
    }

    private fun putSealed(
        ivKey: String,
        ctKey: String,
        sealed: Sealed,
        commit: Boolean,
    ) {
        val editor =
            prefs
                .edit()
                .putString(ivKey, Base64.encodeToString(sealed.iv, Base64.NO_WRAP))
                .putString(ctKey, Base64.encodeToString(sealed.ciphertext, Base64.NO_WRAP))
        // A rotated refresh token must be on disk before it is used: the old one is now dead.
        if (commit) editor.commit() else editor.apply()
    }

    private companion object {
        const val USER_ID = "userId"
        const val DEVICE_ID = "deviceId"
        const val EMAIL = "email"
        const val KDF = "kdf"
        const val WRAPPED = "wrappedVaultKey"
        const val REFRESH_IV = "refreshIv"
        const val REFRESH_CT = "refreshCt"
        const val BIO_IV = "biometricIv"
        const val BIO_CT = "biometricCt"
    }
}
