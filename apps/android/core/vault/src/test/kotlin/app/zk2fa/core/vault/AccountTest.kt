package app.zk2fa.core.vault

import app.zk2fa.core.api.Kdf
import app.zk2fa.core.api.KdfParams
import app.zk2fa.core.crypto.CryptoErrorCode
import app.zk2fa.core.crypto.CryptoException
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.File

class AccountTest {
    private val v =
        Json
            .parseToJsonElement(File(System.getProperty("veilauth.specDir"), "test-vectors.json").readText())
            .jsonObject
            .getValue("keyHierarchy")
            .jsonArray[0]
            .jsonObject

    private fun s(k: String) = v.getValue(k).jsonPrimitive.content

    private fun account(m: Long = 65536): StoredAccount {
        val kdf = v.getValue("kdf").jsonObject
        val p = kdf.getValue("params").jsonObject
        return StoredAccount(
            userId = s("userId"),
            deviceId = uuidV7(),
            email = s("email"),
            kdf = Kdf("argon2id", 1, KdfParams(m, p.getValue("t").jsonPrimitive.long, 1), kdf.getValue("saltB64").jsonPrimitive.content),
            wrappedVaultKey = s("wrappedVaultKey"),
        )
    }

    @Test
    fun `unlock with the right password returns the vault key`() =
        runTest {
            val key = unlockWithPassword(account(), s("password"))
            assertEquals(s("vaultKeyHex"), key.joinToString("") { "%02x".format(it) })
        }

    @Test
    fun `a wrong password or a weakened KDF is refused`() =
        runTest {
            val wrong = assertThrows<CryptoException> { kotlinx.coroutines.runBlocking { unlockWithPassword(account(), "nope") } }
            assertEquals(CryptoErrorCode.DECRYPT_FAILED, wrong.code)
            val weak = assertThrows<CryptoException> { kotlinx.coroutines.runBlocking { unlockWithPassword(account(m = 1024), s("password")) } }
            assertEquals(CryptoErrorCode.KDF_PARAMS_REJECTED, weak.code)
        }
}
