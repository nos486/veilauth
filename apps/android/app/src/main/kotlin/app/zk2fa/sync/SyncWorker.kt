package app.zk2fa.sync

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import app.zk2fa.container
import app.zk2fa.core.api.ApiException
import app.zk2fa.core.api.CODE_NETWORK
import java.util.concurrent.TimeUnit

/**
 * Background sync. It moves ciphertext only and never needs the vault key: pending edits were
 * encrypted when they were made, and conflicts that need decrypting wait for the next unlock.
 */
class SyncWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val controller = applicationContext.container.controller
        return try {
            controller.backgroundSync()
            Result.success()
        } catch (e: ApiException) {
            if (e.code == CODE_NETWORK || e.code == "INTERNAL" || e.code == "RATE_LIMITED") Result.retry() else Result.success()
        }
    }

    companion object {
        private const val PERIODIC = "sync-periodic"
        private const val NOW = "sync-now"

        private val online = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

        fun schedulePeriodic(context: Context) {
            val request =
                PeriodicWorkRequestBuilder<SyncWorker>(1, TimeUnit.HOURS)
                    .setConstraints(online)
                    .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(PERIODIC, ExistingPeriodicWorkPolicy.KEEP, request)
        }

        /** After a local edit: push as soon as there is a network. */
        fun kick(context: Context) {
            val request =
                OneTimeWorkRequestBuilder<SyncWorker>()
                    .setConstraints(online)
                    .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                    .build()
            WorkManager.getInstance(context).enqueueUniqueWork(NOW, ExistingWorkPolicy.REPLACE, request)
        }

        fun cancelAll(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(PERIODIC)
            WorkManager.getInstance(context).cancelUniqueWork(NOW)
        }
    }
}
