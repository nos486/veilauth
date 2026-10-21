package app.zk2fa.core.crypto

import java.security.MessageDigest
import java.text.Normalizer
import javax.crypto.SecretKey

public const val RECOVERY_WORD_COUNT: Int = 24

/** SHA-256 of spec/bip39-english.txt (spec/crypto.md §4). */
private const val WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

private val WORDLIST: List<String> by lazy {
    val bytes =
        Bip39::class.java.getResourceAsStream("bip39-english.txt")?.use { it.readBytes() }
            ?: error("BIP39 word list is missing from the build")
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    check(digest == WORDLIST_SHA256) { "BIP39 word list does not match spec/bip39-english.txt" }
    val words = String(bytes, Charsets.UTF_8).split('\n').filter { it.isNotEmpty() }
    check(words.size == 2048) { "BIP39 word list must have 2048 words" }
    words
}

private val WORD_INDEX: Map<String, Int> by lazy { WORDLIST.withIndex().associate { (i, w) -> w to i } }

/**
 * BIP39 used **only as an encoding** of 32 bytes: 256 bits + 8 checksum bits (first byte of
 * SHA-256) → 24 × 11-bit word indices. The BIP39 seed function is never used.
 */
internal object Bip39 {
    fun encode(entropy: ByteArray): String {
        val checksum = MessageDigest.getInstance("SHA-256").digest(entropy)[0]
        val bits = concat(entropy, byteArrayOf(checksum))
        return (0 until RECOVERY_WORD_COUNT).joinToString(" ") { WORDLIST[readBits(bits, it * 11, 11)] }
    }

    fun decode(words: List<String>): ByteArray {
        val bits = ByteArray(KEY_BYTES + 1)
        words.forEachIndexed { i, w ->
            val index = WORD_INDEX[w] ?: throw CryptoException(CryptoErrorCode.INVALID_MNEMONIC)
            writeBits(bits, i * 11, 11, index)
        }
        val entropy = bits.copyOf(KEY_BYTES)
        val checksum = MessageDigest.getInstance("SHA-256").digest(entropy)[0]
        if (checksum != bits[KEY_BYTES]) {
            wipe(entropy)
            throw CryptoException(CryptoErrorCode.INVALID_MNEMONIC)
        }
        wipe(bits)
        return entropy
    }

    private fun readBits(
        data: ByteArray,
        offset: Int,
        count: Int,
    ): Int {
        var v = 0
        for (i in offset until offset + count) {
            v = (v shl 1) or ((data[i / 8].toInt() ushr (7 - i % 8)) and 1)
        }
        return v
    }

    private fun writeBits(
        data: ByteArray,
        offset: Int,
        count: Int,
        value: Int,
    ) {
        for (j in 0 until count) {
            if ((value ushr (count - 1 - j)) and 1 == 1) {
                val i = offset + j
                data[i / 8] = (data[i / 8].toInt() or (1 shl (7 - i % 8))).toByte()
            }
        }
    }
}

public fun generateRecoveryKey(): ByteArray = randomBytes(KEY_BYTES)

/** 32 bytes → 24 BIP39 English words. */
public fun recoveryKeyToMnemonic(recoveryKey: ByteArray): String {
    if (recoveryKey.size != KEY_BYTES) throw CryptoException(CryptoErrorCode.INVALID_MNEMONIC)
    return Bip39.encode(recoveryKey)
}

private val JS_WHITESPACE_RUN = Regex("[\\u0009-\\u000D\\u0020\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]+")

public fun normalizeMnemonic(input: String): String =
    Normalizer
        .normalize(input, Normalizer.Form.NFKD)
        .jsTrim()
        .lowercase()
        .split(JS_WHITESPACE_RUN)
        .joinToString(" ")

/** 24 words → 32 bytes; verifies the checksum. */
public fun mnemonicToRecoveryKey(input: String): ByteArray {
    val words = normalizeMnemonic(input).split(' ')
    if (words.size != RECOVERY_WORD_COUNT) throw CryptoException(CryptoErrorCode.INVALID_MNEMONIC)
    return Bip39.decode(words)
}

public class RecoveryKeys(
    /** sent to the server on recovery; hashed there like authKey */
    public val recoveryAuth: ByteArray,
    /** wraps the vault key a second time */
    public val recoveryKek: SecretKey,
)

public fun deriveRecoveryKeys(recoveryKey: ByteArray): RecoveryKeys =
    RecoveryKeys(hkdfSha256(recoveryKey, INFO_RECOVERY_AUTH), hkdfToAesKey(recoveryKey, INFO_RECOVERY_KEK))
