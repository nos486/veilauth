package app.zk2fa.core.crypto

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.SecureRandom

private const val B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

/** base64url without padding (spec/crypto.md §0). */
public fun toBase64Url(bytes: ByteArray): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

/** Strict base64url decode: no padding, no whitespace, canonical trailing bits (D-004). */
public fun fromBase64Url(s: String): ByteArray {
    if (s.length % 4 == 1) throw CryptoException(CryptoErrorCode.INVALID_ENCODING)
    val out = ByteArray(s.length * 3 / 4)
    var buffer = 0
    var bits = 0
    var idx = 0
    for (ch in s) {
        val v = B64U.indexOf(ch)
        if (v < 0) throw CryptoException(CryptoErrorCode.INVALID_ENCODING)
        buffer = ((buffer shl 6) or v) and 0xffffff
        bits += 6
        if (bits >= 8) {
            out[idx++] = ((buffer ushr (bits - 8)) and 0xff).toByte()
            bits -= 8
        }
    }
    if ((buffer and ((1 shl bits) - 1)) != 0) throw CryptoException(CryptoErrorCode.INVALID_ENCODING)
    return out
}

/**
 * UTF-8 like `TextEncoder`: a lone surrogate becomes U+FFFD (the JVM encoder would write `?`),
 * so every client derives the same bytes from the same string.
 */
public fun utf8(s: String): ByteArray {
    val sb = StringBuilder(s.length)
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
            sb.append(c).append(s[i + 1])
            i += 2
            continue
        }
        sb.append(if (Character.isSurrogate(c)) '�' else c)
        i++
    }
    return sb.toString().toByteArray(Charsets.UTF_8)
}

/** Strict UTF-8 decode (malformed input → INVALID_ENCODING). A leading BOM is dropped, as `TextDecoder` does. */
public fun fromUtf8(bytes: ByteArray): String {
    val decoder =
        Charsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
    val text =
        try {
            decoder.decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: CharacterCodingException) {
            throw CryptoException(CryptoErrorCode.INVALID_ENCODING)
        }
    return text.removePrefix("﻿")
}

/** Constant-time equality for equal-length inputs; length mismatch returns false immediately (lengths are public). */
public fun constantTimeEqual(
    a: ByteArray,
    b: ByteArray,
): Boolean = a.size == b.size && java.security.MessageDigest.isEqual(a, b)

/** Best-effort wipe of key material held in memory. */
public fun wipe(vararg arrays: ByteArray?) {
    for (a in arrays) a?.fill(0)
}

private val random = SecureRandom()

public fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

internal fun concat(vararg parts: ByteArray): ByteArray {
    val out = ByteArray(parts.sumOf { it.size })
    var off = 0
    for (p in parts) {
        p.copyInto(out, off)
        off += p.size
    }
    return out
}

/** ECMAScript WhiteSpace + LineTerminator, so trimming matches `String.prototype.trim` on the web. */
internal fun Char.isJsWhitespace(): Boolean =
    when (this) {
        '\u0009', '\u000A', '\u000B', '\u000C', '\u000D', ' ', ' ', ' ',
        ' ', ' ', ' ', ' ', '　', '﻿',
        -> true
        else -> this in ' '..' '
    }

internal fun String.jsTrim(): String = trim { it.isJsWhitespace() }
