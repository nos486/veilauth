package app.zk2fa.ui

import app.zk2fa.core.crypto.TokenItem
import app.zk2fa.core.otp.OtpAlgorithm
import app.zk2fa.core.otp.OtpException
import app.zk2fa.core.otp.base32Decode
import app.zk2fa.core.otp.hotp
import app.zk2fa.core.otp.steam
import app.zk2fa.core.otp.totp

/** Current code for a token, or null if the stored secret is unusable. */
fun codeFor(
    t: TokenItem,
    nowMs: Long,
): String? {
    val secret =
        try {
            base32Decode(t.secret)
        } catch (_: OtpException) {
            return null
        }
    return try {
        val algorithm = OtpAlgorithm.valueOf(t.algorithm)
        when (t.type) {
            "hotp" -> hotp(secret, t.counter, t.digits, algorithm)
            "steam" -> steam(secret, nowMs)
            else -> totp(secret, nowMs, t.period, t.digits, algorithm)
        }
    } catch (_: OtpException) {
        null
    } catch (_: IllegalArgumentException) {
        null
    } finally {
        secret.fill(0)
    }
}

/** "123456" → "123 456" for reading; Steam codes stay as they are. */
fun groupCode(code: String): String =
    when (code.length) {
        6 -> code.substring(0, 3) + " " + code.substring(3)
        7 -> code.substring(0, 3) + " " + code.substring(3)
        8 -> code.substring(0, 4) + " " + code.substring(4)
        else -> code
    }

fun title(t: TokenItem): String = t.issuer.ifEmpty { t.account.ifEmpty { "Unnamed" } }
