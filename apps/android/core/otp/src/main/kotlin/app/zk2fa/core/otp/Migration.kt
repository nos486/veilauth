package app.zk2fa.core.otp

import java.util.Base64

/*
 * Decoder for Google Authenticator export QR codes:
 *   otpauth-migration://offline?data=<base64 MigrationPayload protobuf>
 *
 * message MigrationPayload {
 *   repeated OtpParameters otp_parameters = 1;
 *   int32 version = 2; int32 batch_size = 3; int32 batch_index = 4; int32 batch_id = 5;
 * }
 * message OtpParameters {
 *   bytes secret = 1; string name = 2; string issuer = 3;
 *   Algorithm algorithm = 4;  // 0 unspecified(SHA1) 1 SHA1 2 SHA256 3 SHA512 4 MD5
 *   DigitCount digits = 5;    // 0 unspecified(6) 1 SIX 2 EIGHT
 *   OtpType type = 6;         // 0 unspecified(TOTP) 1 HOTP 2 TOTP
 *   int64 counter = 7;
 * }
 */

public sealed interface MigrationEntry {
    public data class Ok(
        val value: OtpParams,
    ) : MigrationEntry

    public data class Failed(
        val error: OtpErrorCode,
        val issuer: String,
        val account: String,
    ) : MigrationEntry
}

public data class MigrationPayload(
    val version: Int,
    val batchSize: Int,
    val batchIndex: Int,
    val batchId: Int,
    val entries: List<MigrationEntry>,
)

private const val MAX_PAYLOAD_BYTES = 64 * 1024

private fun fail(): OtpException = OtpException(OtpErrorCode.MIGRATION_DECODE_FAILED)

private class Reader(
    private val buf: ByteArray,
) {
    var pos = 0

    val done: Boolean get() = pos >= buf.size

    fun varint(): Long {
        var result = 0L
        var shift = 0
        while (shift < 70) {
            if (pos >= buf.size) throw fail()
            val b = buf[pos++].toInt() and 0xff
            if (shift < 64) result = result or ((b and 0x7f).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
        throw fail()
    }

    fun bytes(): ByteArray {
        val len = varint()
        if (len < 0 || len > buf.size - pos) throw fail()
        val out = buf.copyOfRange(pos, pos + len.toInt())
        pos += len.toInt()
        return out
    }

    fun skip(wireType: Int) {
        when (wireType) {
            0 -> varint()
            1 -> advance(8)
            2 -> bytes()
            5 -> advance(4)
            else -> throw fail()
        }
    }

    private fun advance(n: Int) {
        if (n > buf.size - pos) throw fail()
        pos += n
    }
}

private fun str(bytes: ByteArray): String = strictUtf8(bytes) ?: throw fail()

private class RawOtp {
    var secret = ByteArray(0)
    var name = ""
    var issuer = ""
    var algorithm = 0
    var digits = 0
    var type = 0
    var counter = 0L
}

private class Tag(
    raw: Long,
) {
    // `tag >>> 3` in the JS decoder works on the low 32 bits.
    val field: Int = ((raw and 0xffffffffL) ushr 3).toInt()
    val wire: Int = (raw and 7).toInt()
}

private fun readOtp(bytes: ByteArray): RawOtp {
    val r = Reader(bytes)
    val o = RawOtp()
    while (!r.done) {
        val tag = Tag(r.varint())
        when {
            tag.field == 1 && tag.wire == 2 -> o.secret = r.bytes()
            tag.field == 2 && tag.wire == 2 -> o.name = str(r.bytes())
            tag.field == 3 && tag.wire == 2 -> o.issuer = str(r.bytes())
            // int32 fields are sign-extended to 64 bits on the wire.
            tag.field == 4 && tag.wire == 0 -> o.algorithm = r.varint().toInt()
            tag.field == 5 && tag.wire == 0 -> o.digits = r.varint().toInt()
            tag.field == 6 && tag.wire == 0 -> o.type = r.varint().toInt()
            tag.field == 7 && tag.wire == 0 -> o.counter = r.varint()
            else -> r.skip(tag.wire)
        }
    }
    return o
}

private fun toEntry(o: RawOtp): MigrationEntry {
    val issuer = o.issuer.jsTrim()
    var account = o.name.jsTrim()
    if (issuer.isEmpty()) {
        val split = splitLabel(o.name)
        if (split.issuer.isNotEmpty()) return convert(o, split.issuer, split.account)
    } else if (account.startsWith("$issuer:")) {
        account = account.substring(issuer.length + 1).jsTrim()
    }
    return convert(o, issuer, account)
}

private fun convert(
    o: RawOtp,
    issuer: String,
    account: String,
): MigrationEntry {
    fun bad(error: OtpErrorCode) = MigrationEntry.Failed(error, issuer, account)
    val algorithm =
        when (o.algorithm) {
            0, 1 -> OtpAlgorithm.SHA1
            2 -> OtpAlgorithm.SHA256
            3 -> OtpAlgorithm.SHA512
            else -> return bad(OtpErrorCode.INVALID_ALGORITHM)
        }
    val digits =
        when (o.digits) {
            0, 1 -> 6
            2 -> 8
            else -> return bad(OtpErrorCode.INVALID_DIGITS)
        }
    if (o.secret.isEmpty() || o.secret.size > MAX_SECRET_BYTES) return bad(OtpErrorCode.INVALID_SECRET)
    val type =
        when (o.type) {
            1 -> OtpType.HOTP
            0, 2 -> OtpType.TOTP
            else -> return bad(OtpErrorCode.UNSUPPORTED_TYPE)
        }
    var counter = 0L
    if (type == OtpType.HOTP) {
        if (o.counter < 0 || o.counter > MAX_SAFE_INTEGER) return bad(OtpErrorCode.INVALID_COUNTER)
        counter = o.counter
    }
    return MigrationEntry.Ok(
        OtpParams(type, issuer, account, base32Encode(o.secret), algorithm, digits, DEFAULT_PERIOD, counter),
    )
}

private val BASE64_RE = Regex("[A-Za-z0-9+/]*")

private fun base64ToBytes(b64: String): ByteArray {
    // Accept standard and url-safe alphabets; a literal '+' may have been turned into a space.
    val s =
        b64
            .replace(' ', '+')
            .replace('-', '+')
            .replace('_', '/')
            .trimEnd('=')
    if (!BASE64_RE.matches(s) || s.length % 4 == 1) throw fail()
    return try {
        Base64.getDecoder().decode(s + "=".repeat((4 - s.length % 4) % 4))
    } catch (_: IllegalArgumentException) {
        throw fail()
    }
}

private val MIGRATION_RE = Regex("otpauth-migration://offline/?\\?(.*)", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))

/** Decodes one otpauth-migration:// URI. Per-entry problems are reported in `entries`, not thrown. */
public fun decodeMigrationUri(input: String): MigrationPayload {
    val m = MIGRATION_RE.matchEntire(input.jsTrim()) ?: throw OtpException(OtpErrorCode.INVALID_URI)
    var data: String? = null
    for (part in m.groupValues[1].split('&')) {
        if (part.startsWith("data=")) {
            data = decodeUriComponent(part.substring(5)) ?: throw OtpException(OtpErrorCode.INVALID_URI)
            break
        }
    }
    if (data.isNullOrEmpty()) throw OtpException(OtpErrorCode.INVALID_URI)
    if (data.length.toLong() * 3 > MAX_PAYLOAD_BYTES.toLong() * 4 + 12) throw fail()
    return decodeMigrationPayload(base64ToBytes(data))
}

public fun decodeMigrationPayload(bytes: ByteArray): MigrationPayload {
    val r = Reader(bytes)
    var version = 0
    var batchSize = 1
    var batchIndex = 0
    var batchId = 0
    val entries = mutableListOf<MigrationEntry>()
    while (!r.done) {
        val tag = Tag(r.varint())
        when {
            tag.field == 1 && tag.wire == 2 -> entries.add(toEntry(readOtp(r.bytes())))
            tag.field == 2 && tag.wire == 0 -> version = r.varint().toInt()
            tag.field == 3 && tag.wire == 0 -> batchSize = r.varint().toInt()
            tag.field == 4 && tag.wire == 0 -> batchIndex = r.varint().toInt()
            tag.field == 5 && tag.wire == 0 -> batchId = r.varint().toInt()
            else -> r.skip(tag.wire)
        }
    }
    if (batchSize < 1 || batchIndex < 0 || batchIndex >= batchSize) throw fail()
    return MigrationPayload(version, batchSize, batchIndex, batchId, entries)
}

public sealed interface BatchAddResult {
    public data class Incomplete(
        val received: Int,
        val total: Int,
    ) : BatchAddResult

    public data class Duplicate(
        val received: Int,
        val total: Int,
    ) : BatchAddResult

    public data class Complete(
        val entries: List<MigrationEntry>,
    ) : BatchAddResult
}

/** Collects the QR codes of a multi-QR Google Authenticator export (same batchId) in any order. */
public class MigrationBatch {
    private var batchId: Int? = null
    private var total = 0
    private val parts = HashMap<Int, List<MigrationEntry>>()

    public fun add(payload: MigrationPayload): BatchAddResult {
        val id = batchId
        if (id == null) {
            batchId = payload.batchId
            total = payload.batchSize
        } else if (payload.batchId != id || payload.batchSize != total) {
            throw OtpException(OtpErrorCode.MIGRATION_DECODE_FAILED, "QR code belongs to a different export")
        }
        if (payload.batchIndex in parts) return BatchAddResult.Duplicate(parts.size, total)
        parts[payload.batchIndex] = payload.entries
        if (parts.size < total) return BatchAddResult.Incomplete(parts.size, total)
        return BatchAddResult.Complete((0 until total).flatMap { parts[it].orEmpty() })
    }
}
