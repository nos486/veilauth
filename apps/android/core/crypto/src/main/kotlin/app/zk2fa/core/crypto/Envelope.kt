package app.zk2fa.core.crypto

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

public const val ENVELOPE_VERSION: Int = 0x01
public const val NONCE_BYTES: Int = 12
public const val TAG_BYTES: Int = 16
public const val ENVELOPE_OVERHEAD: Int = 1 + NONCE_BYTES + TAG_BYTES
public const val KEY_BYTES: Int = 32

private const val AES_GCM = "AES/GCM/NoPadding"

/** GCM AAD = version ‖ UTF8(context) (D-003). */
internal fun gcmAad(
    version: Int,
    context: String,
): ByteArray = concat(byteArrayOf(version.toByte()), utf8(context))

/** Wraps raw AES-256 key bytes. The caller keeps ownership of `raw` and should wipe it. */
public fun aesKey(raw: ByteArray): SecretKey {
    if (raw.size != KEY_BYTES) throw CryptoException(CryptoErrorCode.INVALID_ENCODING, "AES key must be 32 bytes")
    return SecretKeySpec(raw, "AES")
}

/** Fixed-nonce variant. Only tests and [sealWithNonceForTesting] may use it. */
internal fun sealWithNonce(
    key: SecretKey,
    plaintext: ByteArray,
    context: String,
    nonce: ByteArray,
): String {
    if (nonce.size != NONCE_BYTES) throw CryptoException(CryptoErrorCode.INVALID_ENVELOPE)
    val cipher = Cipher.getInstance(AES_GCM)
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BYTES * 8, nonce))
    cipher.updateAAD(gcmAad(ENVELOPE_VERSION, context))
    val ct = cipher.doFinal(plaintext)
    return toBase64Url(concat(byteArrayOf(ENVELOPE_VERSION.toByte()), nonce, ct))
}

/** Envelope(key, pt, ctx) with a fresh random nonce (spec/crypto.md §5). */
public fun seal(
    key: SecretKey,
    plaintext: ByteArray,
    context: String,
): String = sealWithNonce(key, plaintext, context, randomBytes(NONCE_BYTES))

public class ParsedEnvelope(
    public val version: Int,
    public val nonce: ByteArray,
    /** ciphertext ‖ tag */
    public val body: ByteArray,
)

public fun parseEnvelope(envelope: String): ParsedEnvelope {
    val raw =
        try {
            fromBase64Url(envelope)
        } catch (_: CryptoException) {
            throw CryptoException(CryptoErrorCode.INVALID_ENVELOPE)
        }
    if (raw.size < ENVELOPE_OVERHEAD || raw[0].toInt() != ENVELOPE_VERSION) throw CryptoException(CryptoErrorCode.INVALID_ENVELOPE)
    return ParsedEnvelope(ENVELOPE_VERSION, raw.copyOfRange(1, 1 + NONCE_BYTES), raw.copyOfRange(1 + NONCE_BYTES, raw.size))
}

/** Opens an envelope; any authentication failure is reported as DECRYPT_FAILED. */
public fun open(
    key: SecretKey,
    envelope: String,
    context: String,
): ByteArray {
    val parsed = parseEnvelope(envelope)
    val cipher = Cipher.getInstance(AES_GCM)
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BYTES * 8, parsed.nonce))
    cipher.updateAAD(gcmAad(parsed.version, context))
    return try {
        cipher.doFinal(parsed.body)
    } catch (_: AEADBadTagException) {
        throw CryptoException(CryptoErrorCode.DECRYPT_FAILED)
    }
}
