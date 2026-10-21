package app.zk2fa.core.otp

public enum class OtpErrorCode {
    INVALID_URI,
    UNSUPPORTED_TYPE,
    MISSING_SECRET,
    INVALID_SECRET,
    INVALID_ALGORITHM,
    INVALID_DIGITS,
    INVALID_PERIOD,
    INVALID_COUNTER,
    INVALID_TIME,
    MIGRATION_DECODE_FAILED,
}

/** Error with a stable code. Messages never echo the input (it may contain a secret). */
public class OtpException(
    public val code: OtpErrorCode,
    message: String = code.name,
) : Exception(message)
