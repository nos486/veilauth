package app.zk2fa.core.api

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException

/** Client-side codes on top of [ApiErrorCode]: the request never got a usable answer. */
public const val CODE_NETWORK: String = "NETWORK"
public const val CODE_BAD_RESPONSE: String = "BAD_RESPONSE"

/** Error from the API (stable `code`) or the network. Never carries request or response bodies. */
public class ApiException(
    public val code: String,
    public val status: Int,
) : Exception(code)

/** Codes after which the session cannot continue: the user has to log in again. */
public val SESSION_ENDING_CODES: Set<String> = setOf("SESSION_REVOKED", "REFRESH_REUSED", "UNAUTHORIZED")

public interface TokenStore {
    public suspend fun loadRefreshToken(): String?

    public suspend fun saveRefreshToken(token: String)
}

private const val REFRESH_MARGIN_MS = 30_000L
private val JSON_TYPE = "application/json".toMediaType()

/**
 * The veilauth HTTP API (spec/api.openapi.yaml). Access tokens live in memory only; refreshes are
 * single-flight so a rotated refresh token is never sent twice (reuse ends every session).
 */
public class ApiClient(
    private val baseUrl: HttpUrl,
    private val http: OkHttpClient,
    private val tokens: TokenStore,
    private val onSessionEnded: (code: String) -> Unit,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val refreshLock = Mutex()

    @Volatile private var accessToken: String? = null

    @Volatile private var accessExpiresAt = 0L

    public fun setAccessToken(
        token: String,
        expiresAt: Long,
    ) {
        accessToken = token
        accessExpiresAt = expiresAt
    }

    public fun clearAccessToken() {
        accessToken = null
        accessExpiresAt = 0
    }

    // ---------------------------------------------------------------- public endpoints

    public suspend fun config(): ConfigResponse = get(ApiPaths.CONFIG, ConfigResponse.serializer(), auth = false)

    public suspend fun time(): TimeResponse = get(ApiPaths.TIME, TimeResponse.serializer(), auth = false)

    public suspend fun prelogin(email: String): PreloginResponse =
        post(ApiPaths.AUTH_PRELOGIN, PreloginRequest(email), PreloginRequest.serializer(), PreloginResponse.serializer(), auth = false)

    public suspend fun login(request: LoginRequest): SessionResponse =
        adopt(post(ApiPaths.AUTH_LOGIN, request, LoginRequest.serializer(), SessionResponse.serializer(), auth = false))

    // ---------------------------------------------------------------- authenticated endpoints

    public suspend fun logout() {
        send(ApiPaths.AUTH_LOGOUT, "POST", null, auth = true).close()
    }

    public suspend fun sync(since: Long): SyncResponse = get("${ApiPaths.SYNC}?since=$since", SyncResponse.serializer(), auth = true)

    public suspend fun push(changes: List<PushChange>): PushResponse =
        post(ApiPaths.SYNC_PUSH, PushRequest(changes), PushRequest.serializer(), PushResponse.serializer(), auth = true)

    public suspend fun devices(): DevicesResponse = get(ApiPaths.DEVICES, DevicesResponse.serializer(), auth = true)

    public suspend fun revokeDevice(id: String) {
        val path = ApiPaths.DEVICES_BY_ID.replace("{id}", java.net.URLEncoder.encode(id, "UTF-8"))
        send(path, "DELETE", null, auth = true).close()
    }

    // ---------------------------------------------------------------- plumbing

    private suspend fun adopt(session: SessionResponse): SessionResponse {
        tokens.saveRefreshToken(session.refreshToken)
        setAccessToken(session.accessToken, session.accessTokenExpiresAt)
        return session
    }

    private suspend fun <T> get(
        path: String,
        response: KSerializer<T>,
        auth: Boolean,
    ): T = decode(send(path, "GET", null, auth), response)

    private suspend fun <B, T> post(
        path: String,
        body: B,
        request: KSerializer<B>,
        response: KSerializer<T>,
        auth: Boolean,
    ): T = decode(send(path, "POST", ApiJson.encodeToString(request, body).toRequestBody(JSON_TYPE), auth), response)

    private suspend fun <T> decode(
        res: Response,
        serializer: KSerializer<T>,
    ): T =
        withContext(Dispatchers.IO) {
            res.use {
                try {
                    ApiJson.decodeFromString(serializer, it.body.string())
                } catch (_: SerializationException) {
                    throw ApiException(CODE_BAD_RESPONSE, it.code)
                } catch (_: IllegalArgumentException) {
                    throw ApiException(CODE_BAD_RESPONSE, it.code)
                } catch (_: IOException) {
                    throw ApiException(CODE_NETWORK, 0)
                }
            }
        }

    private fun url(path: String): HttpUrl {
        val (p, query) = path.split('?', limit = 2).let { it[0] to it.getOrNull(1) }
        return baseUrl
            .newBuilder()
            .encodedPath(baseUrl.encodedPath.trimEnd('/') + p)
            .encodedQuery(query)
            .build()
    }

    private suspend fun execute(request: Request): Response =
        withContext(Dispatchers.IO) {
            try {
                http.newCall(request).execute()
            } catch (_: IOException) {
                throw ApiException(CODE_NETWORK, 0)
            }
        }

    private suspend fun send(
        path: String,
        method: String,
        body: RequestBody?,
        auth: Boolean,
        retried: Boolean = false,
    ): Response {
        if (auth && (accessToken == null || clock() > accessExpiresAt - REFRESH_MARGIN_MS)) refresh()
        val builder =
            Request
                .Builder()
                .url(url(path))
                .header("Accept", "application/json")
                .method(method, body)
        val token = accessToken
        if (auth && token != null) builder.header("Authorization", "Bearer $token")
        val res = execute(builder.build())
        if (res.isSuccessful) return res
        val code = errorCode(res)
        if (auth && code == "TOKEN_EXPIRED" && !retried) {
            clearAccessToken()
            return send(path, method, body, auth, retried = true)
        }
        if (auth && code in SESSION_ENDING_CODES) endSession(code)
        throw ApiException(code, res.code)
    }

    /** Single-flight refresh: callers that queued behind a successful refresh reuse its token. */
    private suspend fun refresh() {
        val before = accessToken
        refreshLock.withLock {
            if (accessToken != null && accessToken != before && clock() <= accessExpiresAt - REFRESH_MARGIN_MS) return
            val refreshToken = tokens.loadRefreshToken()
            if (refreshToken == null) {
                endSession("UNAUTHORIZED")
                throw ApiException("UNAUTHORIZED", 401)
            }
            val body = ApiJson.encodeToString(RefreshRequest.serializer(), RefreshRequest(refreshToken)).toRequestBody(JSON_TYPE)
            val res =
                execute(
                    Request
                        .Builder()
                        .url(url(ApiPaths.AUTH_REFRESH))
                        .header("Accept", "application/json")
                        .post(body)
                        .build(),
                )
            if (!res.isSuccessful) {
                val code = errorCode(res)
                if (code in SESSION_ENDING_CODES) endSession(code)
                throw ApiException(code, res.code)
            }
            val parsed = decode(res, RefreshResponse.serializer())
            tokens.saveRefreshToken(parsed.refreshToken)
            setAccessToken(parsed.accessToken, parsed.accessTokenExpiresAt)
        }
    }

    private fun endSession(code: String) {
        clearAccessToken()
        onSessionEnded(code)
    }

    private suspend fun errorCode(res: Response): String =
        withContext(Dispatchers.IO) {
            res.use {
                val parsed =
                    try {
                        ApiJson.decodeFromString(ApiError.serializer(), it.body.string()).code.name
                    } catch (_: SerializationException) {
                        null
                    } catch (_: IllegalArgumentException) {
                        null
                    } catch (_: IOException) {
                        null
                    }
                parsed ?: if (it.code == 429) "RATE_LIMITED" else if (it.code >= 500) "INTERNAL" else CODE_BAD_RESPONSE
            }
        }
}
