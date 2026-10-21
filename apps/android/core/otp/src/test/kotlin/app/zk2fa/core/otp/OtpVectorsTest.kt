package app.zk2fa.core.otp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.DynamicTest.dynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.assertThrows

class OtpVectorsTest {
    @TestFactory
    fun hotp(): List<DynamicTest> =
        Vectors.section("hotp").map { v ->
            dynamicTest("counter ${v.long("counter")} ${v.str("algorithm")} → ${v.str("code")}") {
                val code = hotp(hex(v.str("secretHex")), v.long("counter"), v.int("digits"), OtpAlgorithm.valueOf(v.str("algorithm")))
                assertEquals(v.str("code"), code)
            }
        }

    @TestFactory
    fun totp(): List<DynamicTest> =
        Vectors.section("totp").map { v ->
            dynamicTest("t=${v.long("timeMs")} ${v.str("algorithm")}/${v.int("period")}/${v.int("digits")}") {
                val code =
                    totp(
                        hex(v.str("secretHex")),
                        v.long("timeMs"),
                        v.int("period"),
                        v.int("digits"),
                        OtpAlgorithm.valueOf(v.str("algorithm")),
                    )
                assertEquals(v.str("code"), code)
            }
        }

    @TestFactory
    fun steam(): List<DynamicTest> =
        Vectors.section("steam").map { v ->
            dynamicTest("${v.str("secretB32")} t=${v.long("timeMs")}") {
                assertEquals(v.str("code"), steam(base32Decode(v.str("secretB32")), v.long("timeMs")))
                val params = parseOtpAuthUri("steam://${v.str("secretB32")}")
                assertEquals(v.str("code"), generateCode(params, v.long("timeMs")))
            }
        }

    @TestFactory
    fun otpauth(): List<DynamicTest> =
        Vectors.section("otpauth").map { v ->
            dynamicTest(v.str("uri")) {
                val expected = v["expected"]
                if (expected != null) {
                    val parsed = parseOtpAuthUri(v.str("uri"))
                    assertEquals(expected.toParams(), parsed)
                    assertEquals(parsed, parseOtpAuthUri(toOtpAuthUri(parsed)))
                } else {
                    val e = assertThrows<OtpException> { parseOtpAuthUri(v.str("uri")) }
                    assertEquals(OtpErrorCode.valueOf(v.str("error")), e.code)
                }
            }
        }

    @TestFactory
    fun migration(): List<DynamicTest> =
        Vectors.section("migration").map { v ->
            dynamicTest(v.str("name")) {
                val uris = v.array("uris").map { it.jsonPrimitiveContent() }
                val error = v["error"]
                if (error != null) {
                    val e = assertThrows<OtpException> { uris.forEach(::decodeMigrationUri) }
                    assertEquals(OtpErrorCode.valueOf(v.str("error")), e.code)
                    return@dynamicTest
                }
                val batch = MigrationBatch()
                var last: BatchAddResult? = null
                // Feed in reverse order: batches may be scanned in any order.
                for (uri in uris.reversed()) {
                    val payload = decodeMigrationUri(uri)
                    assertEquals(v.int("batchId"), payload.batchId)
                    last = batch.add(payload)
                }
                assertEquals(BatchAddResult.Complete(v.array("entries").map { it.toMigrationEntry() }), last)
            }
        }

    @Test
    fun `migration reports progress and duplicates`() {
        val first = migrationUri("two-part-batch")
        val batch = MigrationBatch()
        assertEquals(BatchAddResult.Incomplete(1, 2), batch.add(decodeMigrationUri(first)))
        assertEquals(BatchAddResult.Duplicate(1, 2), batch.add(decodeMigrationUri(first)))
    }

    @Test
    fun `migration rejects mixing exports`() {
        val batch = MigrationBatch()
        batch.add(decodeMigrationUri(migrationUri("two-part-batch")))
        assertThrows<OtpException> { batch.add(decodeMigrationUri(migrationUri("single-payload"))) }
    }

    @Test
    fun `migration tolerates a literal plus turned into a space`() {
        val uri = migrationUri("single-payload")
        val data = decodeUriComponent(uri.substringAfter("data=")) ?: error("bad vector")
        val mangled = "otpauth-migration://offline?data=${data.replace('+', ' ')}"
        assertEquals(decodeMigrationUri(uri), decodeMigrationUri(mangled))
    }

    @Test
    fun `migration rejects garbage with OtpException only`() {
        for (data in listOf("%FF%FF%FF%FF%FF%FF%FF%FF%FF%FF%FF", "CgE", "!!!!", "CP%2F%2F%2F%2F%2F%2F%2F%2F%2F%2Fw%3D%3D")) {
            assertThrows<OtpException> { decodeMigrationUri("otpauth-migration://offline?data=$data") }
        }
    }

    @Test
    fun `base32 round-trips all lengths and matches RFC 4648`() {
        for (n in 0 until 40) {
            val bytes = ByteArray(n) { ((it * 37 + n) and 0xff).toByte() }
            assertArrayEquals(bytes, base32Decode(base32Encode(bytes)))
        }
        val cases = listOf("" to "", "f" to "MY", "fo" to "MZXQ", "foo" to "MZXW6", "foob" to "MZXW6YQ", "fooba" to "MZXW6YTB", "foobar" to "MZXW6YTBOI")
        for ((plain, enc) in cases) assertEquals(enc, base32Encode(plain.toByteArray()))
        assertEquals("MZXW6YTBOI", normalizeBase32(" mzxw 6ytb-oi== "))
        for (bad in listOf("MZXW6YTBO1", "M", "MZX", "MZXW6Y", "MZ")) {
            assertThrows<OtpException> { base32Decode(bad) }
        }
    }

    @Test
    fun `errors never echo the input`() {
        val e = assertThrows<OtpException> { parseOtpAuthUri("otpauth://totp/x?secret=SUPERSECRETVALUE1&digits=99") }
        assertFalse(e.message.orEmpty().contains("SUPERSECRET"))
        assertFalse(OtpParams(OtpType.TOTP, "", "", "SUPERSECRET", OtpAlgorithm.SHA1, 6, 30, 0).toString().contains("SUPERSECRET"))
    }

    @Test
    fun `time helpers`() {
        assertEquals(30, secondsRemaining(0, 30))
        assertEquals(1, secondsRemaining(29_999, 30))
        assertEquals(30, secondsRemaining(30_000, 30))
        assertThrows<OtpException> { totp(ByteArray(10), -1) }
    }

    private fun migrationUri(name: String): String =
        Vectors.section("migration").first { it.str("name") == name }.array("uris")[0].jsonPrimitiveContent()
}

private fun kotlinx.serialization.json.JsonElement.jsonPrimitiveContent(): String =
    (this as kotlinx.serialization.json.JsonPrimitive).content
