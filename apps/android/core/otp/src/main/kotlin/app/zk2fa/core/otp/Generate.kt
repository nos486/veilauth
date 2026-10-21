package app.zk2fa.core.otp

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"

/** RFC 4226 dynamic truncation → 31-bit integer. */
private fun truncated(
    secret: ByteArray,
    counter: Long,
    algorithm: OtpAlgorithm,
): Int {
    if (counter < 0 || counter > MAX_SAFE_INTEGER) throw OtpException(OtpErrorCode.INVALID_COUNTER)
    if (secret.isEmpty()) throw OtpException(OtpErrorCode.INVALID_SECRET)
    val mac = Mac.getInstance(algorithm.macName)
    mac.init(SecretKeySpec(secret, algorithm.macName))
    val hash = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array())
    val offset = hash[hash.size - 1].toInt() and 0x0f
    return ByteBuffer.wrap(hash, offset, 4).int and 0x7fffffff
}

/** RFC 4226 HOTP. */
public fun hotp(
    secret: ByteArray,
    counter: Long,
    digits: Int = DEFAULT_DIGITS,
    algorithm: OtpAlgorithm = OtpAlgorithm.SHA1,
): String {
    if (digits !in 1..10) throw OtpException(OtpErrorCode.INVALID_DIGITS)
    var modulus = 1L
    repeat(digits) { modulus *= 10 }
    val code = truncated(secret, counter, algorithm) % modulus
    return code.toString().padStart(digits, '0')
}

/** Time step for `timeMs` (unix ms). */
public fun timeCounter(
    timeMs: Long,
    period: Int = DEFAULT_PERIOD,
): Long {
    if (timeMs < 0) throw OtpException(OtpErrorCode.INVALID_TIME)
    if (period < 1) throw OtpException(OtpErrorCode.INVALID_PERIOD)
    return timeMs / 1000 / period
}

/** Seconds until the current code expires (1..period). */
public fun secondsRemaining(
    timeMs: Long,
    period: Int = DEFAULT_PERIOD,
): Int = period - ((timeMs / 1000) % period).toInt()

/** RFC 6238 TOTP with T0 = 0. */
public fun totp(
    secret: ByteArray,
    timeMs: Long,
    period: Int = DEFAULT_PERIOD,
    digits: Int = DEFAULT_DIGITS,
    algorithm: OtpAlgorithm = OtpAlgorithm.SHA1,
): String = hotp(secret, timeCounter(timeMs, period), digits, algorithm)

/** Steam Guard: TOTP-SHA1 / 30 s, 5 characters from Steam's 26-letter alphabet. */
public fun steam(
    secret: ByteArray,
    timeMs: Long,
): String {
    var code = truncated(secret, timeCounter(timeMs, DEFAULT_PERIOD), OtpAlgorithm.SHA1)
    val out = StringBuilder(STEAM_DIGITS)
    repeat(STEAM_DIGITS) {
        out.append(STEAM_ALPHABET[code % STEAM_ALPHABET.length])
        code /= STEAM_ALPHABET.length
    }
    return out.toString()
}

/** Code for a stored token. For HOTP the stored counter is used and `timeMs` is ignored. */
public fun generateCode(
    params: OtpParams,
    timeMs: Long,
): String {
    val secret = base32Decode(params.secret)
    try {
        return when (params.type) {
            OtpType.TOTP -> totp(secret, timeMs, params.period, params.digits, params.algorithm)
            OtpType.HOTP -> hotp(secret, params.counter, params.digits, params.algorithm)
            OtpType.STEAM -> steam(secret, timeMs)
        }
    } finally {
        secret.fill(0)
    }
}
