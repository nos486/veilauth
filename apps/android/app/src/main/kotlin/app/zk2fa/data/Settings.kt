package app.zk2fa.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Auto-lock choices in seconds. [NEVER] is offered only with biometric unlock (spec §2). */
object AutoLock {
    const val IMMEDIATELY = 0
    const val NEVER = -1
    val choices = listOf(IMMEDIATELY, 30, 60, 300, 900, NEVER)
}

/** Device-local preferences. None of them is secret. */
class Settings(
    context: Context,
) {
    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    private val _autoLockSeconds = MutableStateFlow(prefs.getInt(AUTO_LOCK, 60))
    val autoLockSeconds: StateFlow<Int> = _autoLockSeconds.asStateFlow()

    private val _biometric = MutableStateFlow(prefs.getBoolean(BIOMETRIC, false))
    val biometric: StateFlow<Boolean> = _biometric.asStateFlow()

    fun setAutoLockSeconds(seconds: Int) {
        prefs.edit().putInt(AUTO_LOCK, seconds).apply()
        _autoLockSeconds.value = seconds
    }

    fun setBiometric(enabled: Boolean) {
        prefs.edit().putBoolean(BIOMETRIC, enabled).apply()
        _biometric.value = enabled
        if (!enabled && autoLockSeconds.value == AutoLock.NEVER) setAutoLockSeconds(300)
    }

    private companion object {
        const val AUTO_LOCK = "autoLockSeconds"
        const val BIOMETRIC = "biometric"
    }
}
