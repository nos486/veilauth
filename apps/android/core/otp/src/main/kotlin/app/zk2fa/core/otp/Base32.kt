package app.zk2fa.core.otp

private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

/** RFC 4648 base32 encode, upper-case, no padding. */
public fun base32Encode(bytes: ByteArray): String {
    val out = StringBuilder((bytes.size * 8 + 4) / 5)
    var buffer = 0
    var bits = 0
    for (byte in bytes) {
        buffer = (buffer shl 8) or (byte.toInt() and 0xff)
        bits += 8
        while (bits >= 5) {
            out.append(ALPHABET[(buffer ushr (bits - 5)) and 31])
            bits -= 5
        }
        buffer = buffer and ((1 shl bits) - 1)
    }
    if (bits > 0) out.append(ALPHABET[(buffer shl (5 - bits)) and 31])
    return out.toString()
}

/**
 * Normalise user / URI supplied base32: strips spaces, hyphens and trailing `=`, upper-cases.
 * Throws INVALID_SECRET when the result is not canonical RFC 4648 base32.
 */
public fun normalizeBase32(input: String): String {
    val s = input.filterNot { it.isJsWhitespace() || it == '-' }.trimEnd('=').uppercase()
    base32Decode(s)
    return s
}

/** Strict decode of canonical, unpadded, upper-case base32. Rejects impossible lengths and non-zero trailing bits. */
public fun base32Decode(s: String): ByteArray {
    val rem = s.length % 8
    if (rem == 1 || rem == 3 || rem == 6) throw OtpException(OtpErrorCode.INVALID_SECRET)
    val out = ByteArray(s.length * 5 / 8)
    var buffer = 0
    var bits = 0
    var idx = 0
    for (ch in s) {
        val v = ALPHABET.indexOf(ch)
        if (v < 0) throw OtpException(OtpErrorCode.INVALID_SECRET)
        buffer = ((buffer shl 5) or v) and 0xffff
        bits += 5
        if (bits >= 8) {
            out[idx++] = ((buffer ushr (bits - 8)) and 0xff).toByte()
            bits -= 8
        }
    }
    if ((buffer and ((1 shl bits) - 1)) != 0) throw OtpException(OtpErrorCode.INVALID_SECRET)
    return out
}
