package app.zk2fa.net

import app.zk2fa.BuildConfig
import okhttp3.CertificatePinner
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

object Network {
    val apiBaseUrl: HttpUrl = BuildConfig.API_BASE_URL.toHttpUrl()

    /** API client: TLS via the system trust store plus SPKI pins for the API host (D-047). */
    fun apiClient(): OkHttpClient {
        val builder =
            OkHttpClient
                .Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .followRedirects(false)
                .retryOnConnectionFailure(true)
        val pins = BuildConfig.CERT_PINS.split(',').map(String::trim).filter { it.startsWith("sha256/") }
        if (pins.isNotEmpty()) {
            builder.certificatePinner(CertificatePinner.Builder().add(apiBaseUrl.host, *pins.toTypedArray()).build())
        }
        return builder.build()
    }

    /** GitHub Releases for the updater. Not pinned: every APK is checked by hash and signature. */
    fun downloadClient(): OkHttpClient =
        OkHttpClient
            .Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .build()
}
