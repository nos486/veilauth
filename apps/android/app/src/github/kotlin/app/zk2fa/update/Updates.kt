package app.zk2fa.update

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import app.zk2fa.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/** `android-update.json`, attached to every GitHub Release by .github/workflows/release.yml. */
@Serializable
private data class ReleaseManifest(
    val versionName: String,
    val versionCode: Int,
    val apk: String,
    val sha256: String,
)

fun createUpdater(
    context: Context,
    http: OkHttpClient,
): Updater = GitHubUpdater(context.applicationContext, http)

/**
 * D-019: check GitHub Releases, download the APK, verify its SHA-256 against the release
 * manifest and its signing certificate against the installed app's, then install it with a
 * PackageInstaller session. No code is ever loaded from the network.
 */
private class GitHubUpdater(
    private val context: Context,
    private val http: OkHttpClient,
) : Updater {
    private val json = Json { ignoreUnknownKeys = true }

    override val supported = true

    private fun get(url: String): String {
        val request =
            Request
                .Builder()
                .url(url)
                .header("Accept", "application/vnd.github+json")
                .build()
        http.newCall(request).execute().use { res ->
            if (!res.isSuccessful) throw UpdateException("HTTP_${res.code}")
            return res.body.string()
        }
    }

    override suspend fun check(): UpdateInfo? =
        withContext(Dispatchers.IO) {
            try {
                val release = json.parseToJsonElement(get("https://api.github.com/repos/${BuildConfig.GITHUB_REPO}/releases/latest")).jsonObject
                val assets = release.getValue("assets").jsonArray.map { it.jsonObject }
                fun assetUrl(name: String) =
                    assets.firstOrNull { it["name"]?.jsonPrimitive?.content == name }?.get("browser_download_url")?.jsonPrimitive?.content
                val manifestUrl = assetUrl(MANIFEST) ?: return@withContext null
                val manifest = json.decodeFromString(ReleaseManifest.serializer(), get(manifestUrl))
                if (manifest.versionCode <= BuildConfig.VERSION_CODE) return@withContext null
                val apkUrl = assetUrl(manifest.apk) ?: throw UpdateException("APK_MISSING")
                UpdateInfo(manifest.versionName, manifest.versionCode, apkUrl, manifest.sha256.lowercase())
            } catch (e: IOException) {
                throw UpdateException("NETWORK")
            } catch (e: IllegalArgumentException) {
                throw UpdateException("BAD_MANIFEST")
            } catch (e: NoSuchElementException) {
                throw UpdateException("BAD_MANIFEST")
            }
        }

    override suspend fun install(info: UpdateInfo) {
        val apk = withContext(Dispatchers.IO) { download(info) }
        withContext(Dispatchers.IO) {
            verify(apk, info)
            commit(apk)
        }
    }

    private fun download(info: UpdateInfo): File {
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }
        val file = File(dir, "veilauth-${info.versionCode}.apk")
        val digest = MessageDigest.getInstance("SHA-256")
        try {
            http.newCall(Request.Builder().url(info.apkUrl).build()).execute().use { res ->
                if (!res.isSuccessful) throw UpdateException("HTTP_${res.code}")
                res.body.byteStream().use { input ->
                    file.outputStream().use { output ->
                        val buf = ByteArray(64 * 1024)
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            digest.update(buf, 0, n)
                            output.write(buf, 0, n)
                        }
                    }
                }
            }
        } catch (e: IOException) {
            file.delete()
            throw UpdateException("NETWORK")
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }
        if (actual != info.sha256) {
            file.delete()
            throw UpdateException("HASH_MISMATCH")
        }
        return file
    }

    @Suppress("DEPRECATION")
    private fun signerDigests(info: PackageInfo?): Set<String> {
        if (info == null) return emptySet()
        val signatures =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val signing = info.signingInfo ?: return emptySet()
                if (signing.hasMultipleSigners()) signing.apkContentsSigners else signing.signingCertificateHistory
            } else {
                info.signatures
            }
        return signatures.orEmpty().mapTo(HashSet()) { sig ->
            MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
        }
    }

    @Suppress("DEPRECATION")
    private fun verify(
        apk: File,
        info: UpdateInfo,
    ) {
        val pm = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        val archive = pm.getPackageArchiveInfo(apk.path, flags) ?: throw UpdateException("NOT_AN_APK")
        if (archive.packageName != context.packageName) throw UpdateException("WRONG_PACKAGE")
        val archiveVersion = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) archive.longVersionCode else archive.versionCode.toLong()
        if (archiveVersion != info.versionCode.toLong()) throw UpdateException("WRONG_VERSION")
        // The installed app's own certificate is the pinned release certificate.
        val installed = signerDigests(pm.getPackageInfo(context.packageName, flags))
        val candidate = signerDigests(archive)
        if (installed.isEmpty() || candidate.isEmpty() || candidate.intersect(installed).isEmpty()) {
            apk.delete()
            throw UpdateException("SIGNATURE_MISMATCH")
        }
    }

    private fun commit(apk: File) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        params.setAppPackageName(context.packageName)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        val sessionId = installer.createSession(params)
        installer.openSession(sessionId).use { session ->
            session.openWrite("base.apk", 0, apk.length()).use { out ->
                apk.inputStream().use { it.copyTo(out) }
                session.fsync(out)
            }
            val intent = Intent(context, InstallReceiver::class.java)
            val flags =
                PendingIntent.FLAG_UPDATE_CURRENT or
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0
            val pending = PendingIntent.getBroadcast(context, sessionId, intent, flags)
            session.commit(pending.intentSender)
        }
        apk.delete()
    }

    private companion object {
        const val MANIFEST = "android-update.json"
    }
}
