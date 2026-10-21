package app.zk2fa.update

import android.content.Context
import okhttp3.OkHttpClient

/** F-Droid builds have no updater: F-Droid installs updates itself (D-019). */
fun createUpdater(
    context: Context,
    http: OkHttpClient,
): Updater =
    object : Updater {
        override val supported = false

        override suspend fun check(): UpdateInfo? = null

        override suspend fun install(info: UpdateInfo) = Unit
    }
