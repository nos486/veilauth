package app.zk2fa.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Copies codes marked as sensitive (hidden from the clipboard preview and keyboard suggestions)
 * and clears them again after [CLEAR_AFTER_MS], unless something else was copied meanwhile.
 */
class Clipboard(
    context: Context,
) {
    private val manager = context.getSystemService(ClipboardManager::class.java)
    private val handler = Handler(Looper.getMainLooper())
    private val clearTask = Runnable { clearIfOurs() }

    fun copySensitive(text: String) {
        val clip = ClipData.newPlainText(LABEL, text)
        clip.description.extras =
            PersistableBundle().apply {
                val key = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) ClipDescription.EXTRA_IS_SENSITIVE else LEGACY_SENSITIVE
                putBoolean(key, true)
            }
        manager.setPrimaryClip(clip)
        handler.removeCallbacks(clearTask)
        handler.postDelayed(clearTask, CLEAR_AFTER_MS)
    }

    fun clearIfOurs() {
        handler.removeCallbacks(clearTask)
        // In the background Android may hide the description; clearing then is the safe choice.
        val label = manager.primaryClipDescription?.label
        if (label != null && label != LABEL) return
        manager.clearPrimaryClip()
    }

    companion object {
        const val CLEAR_AFTER_MS = 30_000L
        private const val LABEL = "veilauth code"
        private const val LEGACY_SENSITIVE = "android.content.extra.IS_SENSITIVE"
    }
}
