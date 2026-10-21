package app.zk2fa.core.otp

private val OTPAUTH_RE =
    Regex("otpauth://([^/?#]*)/?([^?#]*)(?:\\?([^#]*))?(?:#.*)?", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
private val STEAM_RE = Regex("steam://([^/?#]+)/?", RegexOption.IGNORE_CASE)
private val UINT_RE = Regex("[0-9]+")

private fun decode(component: String): String =
    decodeUriComponent(component) ?: throw OtpException(OtpErrorCode.INVALID_URI, "malformed percent-encoding")

private fun parseQuery(query: String): Map<String, String> {
    val params = LinkedHashMap<String, String>()
    for (part in query.split('&')) {
        if (part.isEmpty()) continue
        val eq = part.indexOf('=')
        val rawKey = if (eq == -1) part else part.substring(0, eq)
        val rawValue = if (eq == -1) "" else part.substring(eq + 1)
        val key = decode(rawKey.replace('+', ' ')).lowercase()
        if (key !in params) params[key] = decode(rawValue.replace('+', ' '))
    }
    return params
}

/** Validates and normalises a base32 secret; throws INVALID_SECRET / MISSING_SECRET. */
public fun parseSecret(raw: String?): String {
    if (raw == null || raw.jsTrim().isEmpty()) throw OtpException(OtpErrorCode.MISSING_SECRET)
    val secret = normalizeBase32(raw)
    val length = base32Decode(secret).size
    if (length < MIN_SECRET_BYTES || length > MAX_SECRET_BYTES) throw OtpException(OtpErrorCode.INVALID_SECRET)
    return secret
}

public fun parseAlgorithm(raw: String?): OtpAlgorithm {
    if (raw == null) return OtpAlgorithm.SHA1
    return when (raw.jsTrim().uppercase().replaceFirst("-", "")) {
        "SHA1" -> OtpAlgorithm.SHA1
        "SHA256" -> OtpAlgorithm.SHA256
        "SHA512" -> OtpAlgorithm.SHA512
        else -> throw OtpException(OtpErrorCode.INVALID_ALGORITHM)
    }
}

private fun parseUint(
    raw: String,
    code: OtpErrorCode,
): Long {
    if (!UINT_RE.matches(raw)) throw OtpException(code)
    val n = raw.trimStart('0').ifEmpty { "0" }
    if (n.length > 16) throw OtpException(code)
    val value = n.toLong()
    if (value > MAX_SAFE_INTEGER) throw OtpException(code)
    return value
}

public fun validateDigits(
    type: OtpType,
    digits: Long,
): Int {
    if (type == OtpType.STEAM) return STEAM_DIGITS
    if (digits !in 6L..8L) throw OtpException(OtpErrorCode.INVALID_DIGITS)
    return digits.toInt()
}

public fun validatePeriod(period: Long): Int {
    if (period !in 1L..MAX_PERIOD.toLong()) throw OtpException(OtpErrorCode.INVALID_PERIOD)
    return period.toInt()
}

public fun validateCounter(counter: Long): Long {
    if (counter !in 0L..MAX_SAFE_INTEGER) throw OtpException(OtpErrorCode.INVALID_COUNTER)
    return counter
}

private fun steamParams(
    account: String,
    issuer: String,
    secret: String,
): OtpParams =
    OtpParams(
        type = OtpType.STEAM,
        issuer = issuer,
        account = account,
        secret = secret,
        algorithm = OtpAlgorithm.SHA1,
        digits = STEAM_DIGITS,
        period = DEFAULT_PERIOD,
        counter = 0,
    )

public data class Label(
    val issuer: String,
    val account: String,
)

/** Splits "Issuer:account" (first colon). */
public fun splitLabel(label: String): Label {
    val colon = label.indexOf(':')
    if (colon == -1) return Label("", label.jsTrim())
    return Label(label.substring(0, colon).jsTrim(), label.substring(colon + 1).jsTrim())
}

/**
 * Parses `otpauth://totp|hotp|steam/…` (Google Key URI format) and `steam://SECRET`.
 * Steam is detected by type `steam`, `encoder=steam`, or issuer "Steam" (case-insensitive).
 */
public fun parseOtpAuthUri(input: String): OtpParams {
    val uri = input.jsTrim()

    STEAM_RE.matchEntire(uri)?.let { m ->
        return steamParams("", "Steam", parseSecret(decode(m.groupValues[1])))
    }

    val m = OTPAUTH_RE.matchEntire(uri) ?: throw OtpException(OtpErrorCode.INVALID_URI)
    val rawType = m.groupValues[1].lowercase()
    val label = splitLabel(decode(m.groupValues[2]))
    val query = parseQuery(m.groupValues[3])

    if (rawType != "totp" && rawType != "hotp" && rawType != "steam") {
        throw OtpException(OtpErrorCode.UNSUPPORTED_TYPE)
    }
    val issuerParam = query["issuer"]?.jsTrim() ?: ""
    val issuer = issuerParam.ifEmpty { label.issuer }
    val secret = parseSecret(query["secret"])

    val isSteam =
        rawType == "steam" ||
            query["encoder"]?.lowercase() == "steam" ||
            issuer.lowercase() == "steam"
    if (isSteam) return steamParams(label.account, issuer, secret)

    val type = if (rawType == "totp") OtpType.TOTP else OtpType.HOTP
    val algorithm = parseAlgorithm(query["algorithm"])
    val digitsRaw = query["digits"]
    val digits =
        validateDigits(
            type,
            if (digitsRaw == null) DEFAULT_DIGITS.toLong() else parseUint(digitsRaw, OtpErrorCode.INVALID_DIGITS),
        )

    var period = DEFAULT_PERIOD
    var counter = 0L
    if (type == OtpType.TOTP) {
        query["period"]?.let { period = validatePeriod(parseUint(it, OtpErrorCode.INVALID_PERIOD)) }
    } else {
        val counterRaw = query["counter"] ?: throw OtpException(OtpErrorCode.INVALID_COUNTER)
        counter = validateCounter(parseUint(counterRaw, OtpErrorCode.INVALID_COUNTER))
    }

    return OtpParams(type, issuer, label.account, secret, algorithm, digits, period, counter)
}

/** Builds an otpauth:// URI that this parser (and Google Authenticator for totp/hotp) reads back. */
public fun toOtpAuthUri(p: OtpParams): String {
    val enc = ::encodeUriComponent
    val label = if (p.issuer.isEmpty()) enc(p.account) else "${enc(p.issuer)}:${enc(p.account)}"
    val q = mutableListOf("secret=${p.secret}")
    if (p.issuer.isNotEmpty()) q.add("issuer=${enc(p.issuer)}")
    if (p.type == OtpType.STEAM) {
        q.addAll(listOf("encoder=steam", "digits=$STEAM_DIGITS", "period=$DEFAULT_PERIOD"))
        return "otpauth://totp/$label?${q.joinToString("&")}"
    }
    q.add("algorithm=${p.algorithm.name}")
    q.add("digits=${p.digits}")
    q.add(if (p.type == OtpType.TOTP) "period=${p.period}" else "counter=${p.counter}")
    return "otpauth://${p.type.wireName}/$label?${q.joinToString("&")}"
}
