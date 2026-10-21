package app.zk2fa.update

/** A newer signed release found by the updater. */
data class UpdateInfo(
    val versionName: String,
    val versionCode: Int,
    val apkUrl: String,
    val sha256: String,
)

sealed interface UpdateState {
    data object Idle : UpdateState

    data object Checking : UpdateState

    data object UpToDate : UpdateState

    data class Available(
        val info: UpdateInfo,
    ) : UpdateState

    data object Downloading : UpdateState

    data object Installing : UpdateState

    data class Failed(
        val reason: String,
    ) : UpdateState
}

/** In-app updates (D-019). The GitHub flavor installs signed APKs; F-Droid has no updater. */
interface Updater {
    val supported: Boolean

    suspend fun check(): UpdateInfo?

    /** Downloads, verifies hash and signing certificate, then hands the APK to PackageInstaller. */
    suspend fun install(info: UpdateInfo)
}
