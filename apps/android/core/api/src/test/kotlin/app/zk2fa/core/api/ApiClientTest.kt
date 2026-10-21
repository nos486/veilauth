package app.zk2fa.core.api

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.OkHttpClient
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.atomic.AtomicInteger

class ApiClientTest {
    private val server = MockWebServer()
    private val refreshes = AtomicInteger()
    private var ended: String? = null
    private var stored: String? = "r0"

    private val tokens =
        object : TokenStore {
            override suspend fun loadRefreshToken(): String? = stored

            override suspend fun saveRefreshToken(token: String) {
                stored = token
            }
        }

    private fun json(
        code: Int,
        body: String,
    ) = MockResponse.Builder().code(code).addHeader("Content-Type", "application/json").body(body).build()

    private fun client(dispatch: (RecordedRequest) -> MockResponse): ApiClient {
        server.dispatcher =
            object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse = dispatch(request)
            }
        return ApiClient(server.url("/"), OkHttpClient(), tokens, { ended = it })
    }

    @BeforeEach
    fun start() = server.start()

    @AfterEach
    fun stop() = server.close()

    private val emptySync = """{"revision":0,"full":true,"items":[]}"""

    @Test
    fun `concurrent requests share one refresh`() =
        runBlocking {
            val api =
                client { req ->
                    when (req.url.encodedPath) {
                        ApiPaths.AUTH_REFRESH -> {
                            val n = refreshes.incrementAndGet()
                            json(200, """{"accessToken":"a$n","accessTokenExpiresAt":${System.currentTimeMillis() + 600_000},"refreshToken":"r$n"}""")
                        }
                        ApiPaths.SYNC -> if (req.headers["Authorization"] == "Bearer a1") json(200, emptySync) else json(401, """{"code":"UNAUTHORIZED","message":"x"}""")
                        else -> json(404, "{}")
                    }
                }
            (1..5).map { async { api.sync(0) } }.awaitAll()
            assertEquals(1, refreshes.get())
            assertEquals("r1", stored)
        }

    @Test
    fun `an expired access token is refreshed and retried once`() =
        runBlocking {
            val api =
                client { req ->
                    when (req.url.encodedPath) {
                        ApiPaths.AUTH_REFRESH -> {
                            refreshes.incrementAndGet()
                            json(200, """{"accessToken":"fresh","accessTokenExpiresAt":${System.currentTimeMillis() + 600_000},"refreshToken":"r2"}""")
                        }
                        else -> if (req.headers["Authorization"] == "Bearer fresh") json(200, emptySync) else json(401, """{"code":"TOKEN_EXPIRED","message":"x"}""")
                    }
                }
            api.setAccessToken("stale", System.currentTimeMillis() + 600_000)
            assertEquals(0, api.sync(0).revision)
            assertEquals(1, refreshes.get())
        }

    @Test
    fun `a reused refresh token ends the session`() =
        runBlocking {
            val api = client { json(401, """{"code":"REFRESH_REUSED","message":"x"}""") }
            val e = assertThrows<ApiException> { runBlocking { api.sync(0) } }
            assertEquals("REFRESH_REUSED", e.code)
            assertEquals("REFRESH_REUSED", ended)
        }

    @Test
    fun `garbage and network failures map to stable codes`() =
        runBlocking {
            val api = client { json(200, "not json") }
            assertEquals(CODE_BAD_RESPONSE, assertThrows<ApiException> { runBlocking { api.config() } }.code)
            val rateLimited = client { MockResponse.Builder().code(429).build() }
            assertEquals("RATE_LIMITED", assertThrows<ApiException> { runBlocking { rateLimited.prelogin("a@b.c") } }.code)
            server.close()
            assertEquals(CODE_NETWORK, assertThrows<ApiException> { runBlocking { api.config() } }.code)
        }
}
