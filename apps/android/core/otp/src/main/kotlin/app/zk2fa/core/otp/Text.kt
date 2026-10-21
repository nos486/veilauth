package app.zk2fa.core.otp

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/** ECMAScript WhiteSpace + LineTerminator, so trimming matches `String.prototype.trim` on the web. */
internal fun Char.isJsWhitespace(): Boolean =
    when (this) {
        '\u0009', '\u000A', '\u000B', '\u000C', '\u000D', ' ', ' ', ' ',
        ' ', ' ', ' ', ' ', '　', '﻿',
        -> true
        else -> this in ' '..' '
    }

internal fun String.jsTrim(): String = trim { it.isJsWhitespace() }

/** Strict UTF-8 decode; a leading BOM is dropped like `TextDecoder` does. */
internal fun strictUtf8(bytes: ByteArray): String? {
    val decoder =
        Charsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
    val text =
        try {
            decoder.decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: CharacterCodingException) {
            return null
        }
    return text.removePrefix("﻿")
}

/** `decodeURIComponent`: returns null on malformed escapes or invalid UTF-8. */
internal fun decodeUriComponent(s: String): String? {
    if ('%' !in s) return s
    val out = StringBuilder(s.length)
    var i = 0
    while (i < s.length) {
        if (s[i] != '%') {
            out.append(s[i++])
            continue
        }
        val bytes = java.io.ByteArrayOutputStream()
        while (i < s.length && s[i] == '%') {
            if (i + 2 >= s.length) return null
            val hi = Character.digit(s[i + 1], 16)
            val lo = Character.digit(s[i + 2], 16)
            if (hi < 0 || lo < 0) return null
            bytes.write(hi * 16 + lo)
            i += 3
        }
        val decoded =
            Charsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
        try {
            out.append(decoded.decode(ByteBuffer.wrap(bytes.toByteArray())))
        } catch (_: CharacterCodingException) {
            return null
        }
    }
    return out.toString()
}

private const val URI_UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"

/** `encodeURIComponent`. */
internal fun encodeUriComponent(s: String): String {
    val out = StringBuilder(s.length)
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (c in URI_UNRESERVED) {
            out.append(c)
            i++
            continue
        }
        val cp = s.codePointAt(i)
        if (Character.isSurrogate(c) && Character.charCount(cp) == 1) {
            throw OtpException(OtpErrorCode.INVALID_URI, "lone surrogate")
        }
        for (b in String(Character.toChars(cp)).toByteArray(Charsets.UTF_8)) {
            out.append('%').append("%02X".format(b.toInt() and 0xff))
        }
        i += Character.charCount(cp)
    }
    return out.toString()
}
