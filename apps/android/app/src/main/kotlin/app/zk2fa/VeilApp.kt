package app.zk2fa

import android.app.Application
import android.content.Context
import androidx.lifecycle.ProcessLifecycleOwner
import app.zk2fa.sync.SyncWorker

class VeilApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        ProcessLifecycleOwner.get().lifecycle.addObserver(container.autoLock)
        if (container.accounts.load() != null) SyncWorker.schedulePeriodic(this)
    }
}

val Context.container: AppContainer get() = (applicationContext as VeilApp).container
