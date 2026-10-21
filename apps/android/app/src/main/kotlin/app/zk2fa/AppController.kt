package app.zk2fa

import android.util.Log
import app.zk2fa.core.api.ApiException
import app.zk2fa.core.api.CODE_NETWORK
import app.zk2fa.core.crypto.CryptoErrorCode
import app.zk2fa.core.crypto.CryptoException
import app.zk2fa.core.crypto.wipe
import app.zk2fa.core.vault.SyncEngine
import app.zk2fa.core.vault.SyncResult
import app.zk2fa.core.vault.Vault
import app.zk2fa.core.vault.VaultKey
import app.zk2fa.core.vault.asSyncApi
import app.zk2fa.core.vault.logIn as onlineLogIn
import app.zk2fa.core.vault.unlockWithPassword as unwrapWithPassword
import app.zk2fa.sync.SyncWorker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed interface Phase {
    /** No account on this device. */
    data object SignedOut : Phase

    /** Account cached, vault key not in memory. */
    data object Locked : Phase

    data class Unlocked(
        val vault: Vault,
    ) : Phase
}

/** User-facing errors with a stable code; the UI maps them to text. */
class UserError(
    val code: String,
) : Exception(code)

/**
 * App state machine: sign-in, unlock, lock and sync. The vault key exists only in memory while
 * [phase] is [Phase.Unlocked].
 */
class AppController(
    private val c: AppContainer,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private val _phase = MutableStateFlow<Phase>(if (c.accounts.load() == null) Phase.SignedOut else Phase.Locked)
    val phase: StateFlow<Phase> = _phase.asStateFlow()

    /** One-line notice for the vault screen (session ended, rollback, sync error); null = none. */
    private val _notice = MutableStateFlow<String?>(null)
    val notice: StateFlow<String?> = _notice.asStateFlow()

    private val _syncing = MutableStateFlow(false)
    val syncing: StateFlow<Boolean> = _syncing.asStateFlow()

    @Volatile private var key: VaultKey? = null

    private val engine = SyncEngine(c.api.asSyncApi(), c.store) { key }

    fun clearNotice() {
        _notice.value = null
    }

    // ------------------------------------------------------------------ sign-in / unlock

    suspend fun logIn(
        email: String,
        password: String,
    ) {
        val result = onlineLogIn(c.api, email, password)
        try {
            val previous = c.accounts.load()
            // A different account on this device: never mix caches.
            if (previous?.userId != result.account.userId) {
                c.store.wipe()
                c.accounts.clearBiometricVaultKey()
                c.settings.setBiometric(false)
            }
            c.accounts.save(result.account)
            enter(VaultKey.of(result.account.userId, result.vaultKey))
        } finally {
            wipe(result.vaultKey)
        }
        SyncWorker.schedulePeriodic(c.app)
    }

    /** Offline unlock; falls back to an online log-in if the password changed on another device. */
    suspend fun unlockWithPassword(password: String) {
        val account = c.accounts.load() ?: throw UserError("NO_ACCOUNT")
        val raw =
            try {
                unwrapWithPassword(account, password)
            } catch (e: CryptoException) {
                if (e.code != CryptoErrorCode.DECRYPT_FAILED) throw e
                try {
                    logIn(account.email, password)
                    return
                } catch (net: ApiException) {
                    if (net.code == CODE_NETWORK || net.code == "INVALID_CREDENTIALS") throw UserError("WRONG_PASSWORD")
                    throw net
                }
            }
        try {
            enter(VaultKey.of(account.userId, raw))
        } finally {
            wipe(raw)
        }
        // The server ended the session earlier: the password is at hand, so sign in again quietly.
        if (!c.accounts.hasRefreshToken()) {
            scope.launch {
                try {
                    logIn(account.email, password)
                } catch (e: ApiException) {
                    _notice.value = "SESSION_ENDED"
                    Log.w(TAG, "re-login failed: ${e.code}")
                }
            }
        }
    }

    /** Biometric unlock: `raw` was just decrypted with the biometric Keystore key. */
    fun unlockWithKey(raw: ByteArray) {
        val account = c.accounts.load() ?: throw UserError("NO_ACCOUNT")
        try {
            enter(VaultKey.of(account.userId, raw))
        } finally {
            wipe(raw)
        }
    }

    private fun enter(vaultKey: VaultKey) {
        key = vaultKey
        _phase.value = Phase.Unlocked(Vault(c.store, vaultKey))
        scope.launch { syncNow() }
    }

    /** Raw vault key for wrapping under the biometric Keystore key; caller wipes it. */
    fun exportKeyForBiometrics(): ByteArray = key?.exportRawForWrapping() ?: throw UserError("LOCKED")

    fun lock() {
        if (_phase.value !is Phase.Unlocked) return
        key = null
        c.api.clearAccessToken()
        c.clipboard.clearIfOurs()
        _phase.value = if (c.accounts.load() == null) Phase.SignedOut else Phase.Locked
    }

    suspend fun logOut() {
        try {
            c.api.logout()
        } catch (e: ApiException) {
            // Offline or already revoked: the local wipe below still signs this device out.
            Log.i(TAG, "logout request failed: ${e.code}")
        }
        SyncWorker.cancelAll(c.app)
        key = null
        c.api.clearAccessToken()
        c.store.wipe()
        c.accounts.clear()
        c.settings.setBiometric(false)
        c.clipboard.clearIfOurs()
        _phase.value = Phase.SignedOut
    }

    /** Called by the API client when the server ended the session (revoked, refresh reuse). */
    fun onSessionEnded(code: String) {
        c.accounts.clearRefreshToken()
        _notice.value = "SESSION_ENDED"
        Log.w(TAG, "session ended: $code")
    }

    // ------------------------------------------------------------------ sync

    /** Foreground sync after unlock and edits. Errors become a notice; edits stay queued. */
    suspend fun syncNow(): SyncResult? {
        if (!c.accounts.hasRefreshToken()) return null
        _syncing.value = true
        return try {
            val result = engine.sync()
            if (result.rollbacks > 0) _notice.value = "ROLLBACK"
            result
        } catch (e: ApiException) {
            if (e.code != CODE_NETWORK) _notice.value = "SYNC_FAILED"
            Log.i(TAG, "sync failed: ${e.code}")
            null
        } finally {
            _syncing.value = false
        }
    }

    /** From [SyncWorker]: same engine; works while locked (ciphertext only). */
    suspend fun backgroundSync() {
        if (c.accounts.load() == null || !c.accounts.hasRefreshToken()) return
        engine.sync()
    }

    /** After a local edit: try now, and let WorkManager retry when offline. */
    fun afterEdit() {
        scope.launch { if (syncNow() == null) SyncWorker.kick(c.app) }
    }

    private companion object {
        const val TAG = "veilauth"
    }
}
