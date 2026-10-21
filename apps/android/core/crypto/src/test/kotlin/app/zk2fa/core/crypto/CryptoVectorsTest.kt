package app.zk2fa.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.DynamicTest.dynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.assertThrows
import java.io.File

/**
 * Mirrors packages/crypto/test/vectors.test.ts. The server-only parts (PBKDF2 authHash, fake
 * prelogin salt) are not client code and are covered by the TypeScript suite.
 */
class CryptoVectorsTest {
    private val vectors: JsonObject by lazy {
        val dir = System.getProperty("veilauth.specDir") ?: error("veilauth.specDir is not set")
        Json.parseToJsonElement(File(dir, "test-vectors.json").readText()).jsonObject
    }

    private fun section(name: String): List<JsonObject> = vectors.getValue(name).jsonArray.map { it.jsonObject }

    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content

    private fun JsonObject.o(key: String): JsonObject = getValue(key).jsonObject

    private fun JsonObject.i(key: String): Int = getValue(key).jsonPrimitive.int

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    private fun JsonObject.kdfParams(): KdfParams = KdfParams(i("m"), i("t"), i("p"))

    /** The items section is encrypted with recovery[*].vaultKeyHex. */
    private val vaultKeyHex: String get() = section("recovery")[0].s("vaultKeyHex")

    private fun ref(v: JsonObject): ItemRef = ItemRef(v.s("userId"), v.s("itemId"), ItemKind.fromWireName(v.s("kind")) ?: error("kind"))

    @TestFactory
    fun argon2id(): List<DynamicTest> =
        vectors.o("argon2id").getValue("reference").jsonArray.map { it.jsonObject }.map { v ->
            dynamicTest(v.s("note")) {
                val out = argon2idRaw(utf8(v.s("passwordUtf8")), utf8(v.s("saltUtf8")), v.kdfParams(), v.i("length"))
                assertEquals(v.s("hashHex"), out.hex())
            }
        }

    @TestFactory
    fun hkdf(): List<DynamicTest> =
        section("hkdf").mapIndexed { n, v ->
            dynamicTest("#$n info=\"${v.s("info")}\"") {
                val length = v["length"]?.jsonPrimitive?.int ?: KEY_BYTES
                assertEquals(v.s("okmHex"), hkdfSha256(hex(v.s("ikmHex")), v.s("info"), length).hex())
            }
        }

    @TestFactory
    fun keyHierarchy(): List<DynamicTest> =
        section("keyHierarchy").map { v ->
            dynamicTest(v.s("name")) {
                val kdf = v.o("kdf")
                val salt = fromBase64Url(kdf.s("saltB64"))
                val params = kdf.o("params").kdfParams()
                assertEquals(v.s("normalizedPasswordHex"), normalizePassword(v.s("password")).hex())

                val mk = deriveMasterKey(v.s("password"), salt, params)
                assertEquals(v.s("masterKeyHex"), mk.hex())
                assertEquals(v.s("authKeyHex"), hkdfSha256(mk, INFO_AUTH).hex())
                assertEquals(v.s("kekHex"), hkdfSha256(mk, INFO_KEK).hex())

                val login = deriveLoginKeys(v.s("password"), salt, params)
                assertEquals(v.s("authKeyB64"), toBase64Url(login.authKey))
                assertEquals(v.s("vaultKeyHex"), unwrapVaultKey(login.kek, v.s("wrappedVaultKey"), v.s("userId")).hex())

                val kek = aesKey(hex(v.s("kekHex")))
                val wrapped = sealWithNonce(kek, hex(v.s("vaultKeyHex")), Ctx.vaultKey(v.s("userId")), hex(v.s("wrapNonceHex")))
                assertEquals(v.s("wrappedVaultKey"), wrapped)
                assertEquals(61, fromBase64Url(wrapped).size)

                val e = assertThrows<CryptoException> { unwrapVaultKey(kek, v.s("wrappedVaultKey"), "0192d5f0-6a3c-7c1e-9b2a-000000000002") }
                assertEquals(CryptoErrorCode.DECRYPT_FAILED, e.code)
            }
        }

    @TestFactory
    fun recovery(): List<DynamicTest> =
        section("recovery").map { v ->
            dynamicTest(v.s("name")) {
                val key = hex(v.s("recoveryKeyHex"))
                val mnemonic = v.s("mnemonic")
                assertEquals(mnemonic, recoveryKeyToMnemonic(key))
                val messy = "  " + mnemonic.uppercase().replace(" ", "  \n") + " "
                assertEquals(v.s("recoveryKeyHex"), mnemonicToRecoveryKey(messy).hex())
                assertEquals(v.s("recoveryKekHex"), hkdfSha256(key, INFO_RECOVERY_KEK).hex())
                assertEquals(v.s("recoveryAuthHex"), hkdfSha256(key, INFO_RECOVERY_AUTH).hex())
                val keys = deriveRecoveryKeys(key)
                assertEquals(v.s("recoveryAuthHex"), keys.recoveryAuth.hex())
                val vk = unwrapVaultKeyWithRecovery(keys.recoveryKek, v.s("recoveryWrappedVaultKey"), v.s("userId"))
                assertEquals(v.s("vaultKeyHex"), vk.hex())
                val rewrapped =
                    sealWithNonce(
                        aesKey(hex(v.s("recoveryKekHex"))),
                        hex(v.s("vaultKeyHex")),
                        Ctx.recoveryVaultKey(v.s("userId")),
                        hex(v.s("wrapNonceHex")),
                    )
                assertEquals(v.s("recoveryWrappedVaultKey"), rewrapped)
            }
        }

    @Test
    fun `mnemonic rejects a bad checksum, wrong word count and unknown words`() {
        val words = section("recovery")[0].s("mnemonic").split(" ")
        val swapped = words.toMutableList().also { it[0] = words[1]; it[1] = words[0] }
        for (bad in listOf(swapped, words.take(12), words.mapIndexed { i, w -> if (i == 3) "notaword" else w })) {
            assertEquals(CryptoErrorCode.INVALID_MNEMONIC, assertThrows<CryptoException> { mnemonicToRecoveryKey(bad.joinToString(" ")) }.code)
        }
    }

    @TestFactory
    fun padding(): List<DynamicTest> =
        section("padding").map { v ->
            dynamicTest(v.s("name")) {
                assertEquals(v.s("canonicalJson"), canonicalJson(v.getValue("value")))
                val padded = padPlaintext(utf8(v.s("canonicalJson")))
                assertEquals(v.i("paddedLength"), padded.size)
                assertEquals(v.s("paddedHex"), padded.hex())
                assertEquals(v.s("canonicalJson"), fromUtf8(unpadPlaintext(padded)))
            }
        }

    @TestFactory
    fun items(): List<DynamicTest> =
        section("items").map { v ->
            dynamicTest(v.s("name")) {
                val plaintext = v.getValue("plaintext")
                assertEquals(v.s("canonicalJson"), canonicalJson(plaintext))
                assertEquals(v.s("aad"), ref(v).context)
                assertEquals(v.s("paddedHex"), padPlaintext(utf8(v.s("canonicalJson"))).hex())

                val key = aesKey(hex(vaultKeyHex))
                assertEquals(v.s("envelope"), encryptItemWithNonce(key, ref(v), plaintext, hex(v.s("nonceHex"))))

                val value = decryptItem(key, ref(v), v.s("envelope"))
                assertEquals(plaintext, value)
                when (ref(v).kind) {
                    ItemKind.TOKEN -> assertEquals(plaintext, validateTokenItem(value).toJson())
                    ItemKind.FOLDER -> assertEquals(plaintext, validateFolderItem(value).toJson())
                    ItemKind.SETTINGS -> Unit
                }
                // A fresh random nonce still round-trips.
                assertEquals(plaintext, decryptItem(key, ref(v), encryptItem(key, ref(v), plaintext)))
            }
        }

    @TestFactory
    fun tamper(): List<DynamicTest> =
        section("tamper").map { v ->
            dynamicTest(v.s("name")) {
                val e = assertThrows<CryptoException> { decryptItem(aesKey(hex(v.s("keyHex"))), ref(v), v.s("envelope")) }
                assertEquals(CryptoErrorCode.valueOf(v.s("error")), e.code)
            }
        }

    @TestFactory
    fun invalidEnvelopes(): List<DynamicTest> =
        section("invalidEnvelopes").map { v ->
            dynamicTest(v.s("name")) {
                val e = assertThrows<CryptoException> { open(aesKey(ByteArray(32)), v.s("envelope"), "x") }
                assertEquals(CryptoErrorCode.valueOf(v.s("error")), e.code)
            }
        }

    @TestFactory
    fun kdfParamsRejected(): List<DynamicTest> =
        section("kdfParamsRejected").map { v ->
            dynamicTest(v.s("name")) {
                val e = assertThrows<CryptoException> { validateKdfParams(v.s("alg"), v.o("params"), fromBase64Url(v.s("saltB64"))) }
                assertEquals(CryptoErrorCode.KDF_PARAMS_REJECTED, e.code)
            }
        }

    @Test
    fun `canonical JSON rejects floats, unsafe integers and lone surrogates`() {
        for (bad in listOf("1.5", "9007199254740992", "\"\\ud800\"", "{\"a\":[1e400]}")) {
            val e = assertThrows<CryptoException> { canonicalJson(Json.parseToJsonElement(bad)) }
            assertEquals(CryptoErrorCode.INVALID_ITEM, e.code)
        }
        assertEquals("[0,1000,1,\"\\u001f\\n\"]", canonicalJson(Json.parseToJsonElement("[-0,1e3,1.0,\"\\u001F\\n\"]")))
    }

    @Test
    fun `token validation preserves unknown keys and redacts the secret`() {
        val base = section("items").first { it.s("kind") == "token" }.o("plaintext")
        val withExtra = JsonObject(base + ("futureField" to JsonPrimitive("x")))
        val token = validateTokenItem(withExtra)
        assertEquals(withExtra, token.toJson())
        assertTrue(!token.toString().contains(token.secret))
        val missing = JsonObject(base - "notes")
        assertEquals(CryptoErrorCode.INVALID_ITEM, assertThrows<CryptoException> { validateTokenItem(missing) }.code)
    }

    @Test
    fun `strict base64url`() {
        assertArrayEquals(byteArrayOf(-5, -1), fromBase64Url("-_8"))
        for (bad in listOf("-_8=", "+/8", "-_9", "a")) {
            assertThrows<CryptoException> { fromBase64Url(bad) }
        }
    }
}
