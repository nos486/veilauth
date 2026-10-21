package app.zk2fa.core.crypto

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import java.nio.ByteBuffer
import javax.crypto.SecretKey

public const val PAD_BUCKET: Int = 256

/** 8192 base64url chars = 6144 bytes − 29 bytes overhead, rounded down to a bucket (D-007). */
public const val MAX_PADDED_BYTES: Int = 5888
public const val MAX_BLOB_CHARS: Int = 8192

/** u32be(len) ‖ data ‖ 0x00… up to the next multiple of 256 (spec/crypto.md §6.2). */
public fun padPlaintext(data: ByteArray): ByteArray {
    val total = (4 + data.size + PAD_BUCKET - 1) / PAD_BUCKET * PAD_BUCKET
    if (total > MAX_PADDED_BYTES) throw CryptoException(CryptoErrorCode.ITEM_TOO_LARGE)
    val out = ByteArray(total)
    ByteBuffer.wrap(out).putInt(data.size)
    data.copyInto(out, 4)
    return out
}

public fun unpadPlaintext(padded: ByteArray): ByteArray {
    if (padded.size < 4 || padded.size % PAD_BUCKET != 0) throw CryptoException(CryptoErrorCode.DECRYPT_FAILED)
    val len = ByteBuffer.wrap(padded).int.toLong() and 0xffffffffL
    if (4 + len > padded.size) throw CryptoException(CryptoErrorCode.DECRYPT_FAILED)
    var nonZero = 0
    for (i in 4 + len.toInt() until padded.size) nonZero = nonZero or padded[i].toInt()
    if (nonZero != 0) throw CryptoException(CryptoErrorCode.DECRYPT_FAILED)
    return padded.copyOfRange(4, 4 + len.toInt())
}

public data class ItemRef(
    val userId: String,
    val itemId: String,
    val kind: ItemKind,
) {
    internal val context: String get() = Ctx.item(userId, itemId, kind)
}

public fun encodeItemPlaintext(value: JsonElement): ByteArray = padPlaintext(utf8(canonicalJson(value)))

/** Encrypts an item with the vault key: JCS → pad → Envelope. */
public fun encryptItem(
    vaultKey: SecretKey,
    ref: ItemRef,
    value: JsonElement,
): String {
    val context = ref.context
    val padded = encodeItemPlaintext(value)
    try {
        return seal(vaultKey, padded, context)
    } finally {
        wipe(padded)
    }
}

/** Fixed-nonce variant for test vectors only. */
internal fun encryptItemWithNonce(
    vaultKey: SecretKey,
    ref: ItemRef,
    value: JsonElement,
    nonce: ByteArray,
): String = sealWithNonce(vaultKey, encodeItemPlaintext(value), ref.context, nonce)

/** Decrypts an item to its JSON value (not yet schema-validated). */
public fun decryptItem(
    vaultKey: SecretKey,
    ref: ItemRef,
    envelope: String,
): JsonElement {
    if (envelope.length > MAX_BLOB_CHARS) throw CryptoException(CryptoErrorCode.INVALID_ENVELOPE)
    val padded = open(vaultKey, envelope, ref.context)
    val json = unpadPlaintext(padded)
    wipe(padded)
    try {
        return Json.parseToJsonElement(fromUtf8(json))
    } catch (_: SerializationException) {
        throw CryptoException(CryptoErrorCode.INVALID_ITEM)
    } catch (e: CryptoException) {
        throw CryptoException(CryptoErrorCode.INVALID_ITEM, e.code.name)
    } finally {
        wipe(json)
    }
}
