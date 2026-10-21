package app.zk2fa.core.api

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class ApiModelsTest {
    @Test
    fun `optional fields are omitted and required nulls are sent`() {
        val request =
            LoginRequest(
                email = "a@example.com",
                authKey = "k".repeat(43),
                device = DeviceInfo(id = "0192d5f0-6a3c-7c1e-8b2a-3f4e5d6c7b8a", platform = Platform.ANDROID, nameEnc = null),
            )
        assertEquals(
            """{"email":"a@example.com","authKey":"${"k".repeat(43)}","device":{"id":"0192d5f0-6a3c-7c1e-8b2a-3f4e5d6c7b8a","platform":"android","nameEnc":null}}""",
            ApiJson.encodeToString(LoginRequest.serializer(), request),
        )
    }

    @Test
    fun `responses tolerate new keys but not a fractional KDF cost`() {
        val json = """{"kdf":{"alg":"argon2id","version":1,"params":{"m":65536,"t":3,"p":1},"salt":"EBESExQVFhcYGRobHB0eHw","later":true}}"""
        assertEquals(65536L, ApiJson.decodeFromString(PreloginResponse.serializer(), json).kdf.params.m)
        assertThrows<IllegalArgumentException> {
            ApiJson.decodeFromString(PreloginResponse.serializer(), json.replace("65536", "65536.5"))
        }
    }

    @Test
    fun `sync items decode with null blobs`() {
        val json = """{"revision":3,"full":false,"items":[{"id":"0192d5f1-0000-7000-8000-000000000001","kind":"token","blob":null,"revision":3,"deleted":true,"updatedAt":1}]}"""
        val response = ApiJson.decodeFromString(SyncResponse.serializer(), json)
        assertEquals(ItemKind.TOKEN, response.items.single().kind)
        assertEquals(null, response.items.single().blob)
    }
}
