package app.zk2fa.core.crypto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal const val MAX_SAFE_INTEGER: Long = 9_007_199_254_740_991L

/** A JSON number that is a safe integer, as `Number.isSafeInteger` sees it after `JSON.parse`. */
internal fun safeIntegerOf(p: JsonPrimitive): Long? {
    if (p.isString || p is JsonNull) return null
    val asLong = p.content.toLongOrNull()
    if (asLong != null) return asLong.takeIf { it in -MAX_SAFE_INTEGER..MAX_SAFE_INTEGER }
    if (p.content == "true" || p.content == "false") return null
    val d = p.content.toDoubleOrNull() ?: return null
    if (d.isNaN() || d.isInfinite() || d != Math.floor(d) || Math.abs(d) > MAX_SAFE_INTEGER.toDouble()) return null
    return d.toLong()
}

private fun fail(reason: String): Nothing = throw CryptoException(CryptoErrorCode.INVALID_ITEM, reason)

/** `JSON.stringify` string escaping; lone surrogates are rejected (D-006). */
private fun quote(
    s: String,
    out: StringBuilder,
) {
    out.append('"')
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
            out.append(c).append(s[i + 1])
            i += 2
            continue
        }
        if (Character.isSurrogate(c)) fail("lone surrogate in string")
        when (c) {
            '"' -> out.append("\\\"")
            '\\' -> out.append("\\\\")
            '\b' -> out.append("\\b")
            '\u000C' -> out.append("\\f")
            '\n' -> out.append("\\n")
            '\r' -> out.append("\\r")
            '\t' -> out.append("\\t")
            else -> if (c < ' ') out.append("\\u").append("%04x".format(c.code)) else out.append(c)
        }
        i++
    }
    out.append('"')
}

private fun write(
    value: JsonElement,
    out: StringBuilder,
) {
    when (value) {
        is JsonNull -> out.append("null")
        is JsonPrimitive ->
            when {
                value.isString -> quote(value.content, out)
                value.content == "true" || value.content == "false" -> out.append(value.content)
                else -> out.append(safeIntegerOf(value) ?: fail("only safe integers are allowed"))
            }
        is JsonArray -> {
            out.append('[')
            value.forEachIndexed { i, v ->
                if (i > 0) out.append(',')
                write(v, out)
            }
            out.append(']')
        }
        is JsonObject -> {
            out.append('{')
            // String.compareTo orders by UTF-16 code units, as RFC 8785 requires.
            value.entries.sortedWith { a, b -> a.key.compareTo(b.key) }.forEachIndexed { i, (k, v) ->
                if (i > 0) out.append(',')
                quote(k, out)
                out.append(':')
                write(v, out)
            }
            out.append('}')
        }
    }
}

/**
 * RFC 8785 (JCS) for the restricted type set of spec/crypto.md §6.1:
 * objects, arrays, strings, booleans, null and safe integers.
 */
public fun canonicalJson(value: JsonElement): String = StringBuilder().also { write(value, it) }.toString()
