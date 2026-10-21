package app.zk2fa

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import app.zk2fa.core.api.ApiClient
import app.zk2fa.data.AccountStore
import app.zk2fa.data.AutoLock
import app.zk2fa.data.RoomVaultStore
import app.zk2fa.data.Settings
import app.zk2fa.data.VaultDatabase
import app.zk2fa.net.Network
import app.zk2fa.security.Clipboard
import app.zk2fa.update.createUpdater

/** Manual dependency graph; one per process. */
class AppContainer(
    val app: Application,
) {
    val settings = Settings(app)
    val accounts = AccountStore(app)
    val store = RoomVaultStore(VaultDatabase.open(app))
    val clipboard = Clipboard(app)
    val updater = createUpdater(app, Network.downloadClient())
    val api: ApiClient = ApiClient(Network.apiBaseUrl, Network.apiClient(), accounts, onSessionEnded = { controller.onSessionEnded(it) })
    val controller = AppController(this)

    /** Locks the vault after the app has been in the background for the chosen time. */
    val autoLock =
        object : DefaultLifecycleObserver {
            private var backgroundSince = 0L

            override fun onStop(owner: LifecycleOwner) {
                backgroundSince = SystemClock.elapsedRealtime()
                if (settings.autoLockSeconds.value == AutoLock.IMMEDIATELY) controller.lock()
            }

            override fun onStart(owner: LifecycleOwner) {
                val seconds = settings.autoLockSeconds.value
                if (seconds == AutoLock.NEVER || backgroundSince == 0L) return
                if (SystemClock.elapsedRealtime() - backgroundSince >= seconds * 1000L) controller.lock()
            }
        }
}
