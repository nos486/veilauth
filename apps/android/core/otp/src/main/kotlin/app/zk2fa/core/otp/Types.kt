package app.zk2fa.core.otp

public enum class OtpAlgorithm(internal val macName: String) {
    SHA1("HmacSHA1"),
    SHA256("HmacSHA256"),
    SHA512("HmacSHA512"),
}

/** Wire names are lower-case (`totp`, `hotp`, `steam`), as in spec/crypto.md §6.3. */
public enum class OtpType(public val wireName: String) {
    TOTP("totp"),
    HOTP("hotp"),
    STEAM("steam"),
    ;

    public companion object {
        public fun fromWireName(name: String): OtpType? = entries.firstOrNull { it.wireName == name }
    }
}

/** Token parameters as stored in the vault (spec/crypto.md §6.3). `secret` is base32, upper-case, unpadded. */
public data class OtpParams(
    val type: OtpType,
    val issuer: String,
    val account: String,
    val secret: String,
    val algorithm: OtpAlgorithm,
    val digits: Int,
    val period: Int,
    val counter: Long,
) {
    override fun toString(): String = "OtpParams(type=$type, issuer=$issuer, account=$account, secret=<redacted>)"
}

public const val DEFAULT_PERIOD: Int = 30
public const val DEFAULT_DIGITS: Int = 6
public const val STEAM_DIGITS: Int = 5
public const val MAX_PERIOD: Int = 86_400
public const val MIN_SECRET_BYTES: Int = 1
public const val MAX_SECRET_BYTES: Int = 128

/** Number.MAX_SAFE_INTEGER, so counters round-trip through the JS clients unchanged. */
public const val MAX_SAFE_INTEGER: Long = 9_007_199_254_740_991L
