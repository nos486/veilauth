package app.zk2fa.core.crypto

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.HKDFParameters
import java.text.Normalizer
import javax.crypto.SecretKey

public const val KDF_ALG: String = "argon2id"
public const val KDF_SALT_BYTES: Int = 16
public const val CURRENT_KDF_VERSION: Int = 1

public const val INFO_AUTH: String = "zk2fa/v1/auth"
public const val INFO_KEK: String = "zk2fa/v1/kek"
public const val INFO_RECOVERY_KEK: String = "zk2fa/v1/recovery-kek"
public const val INFO_RECOVERY_AUTH: String = "zk2fa/v1/recovery-auth"

/** Argon2id cost: memory in KiB, passes, lanes. */
public data class KdfParams(
    val m: Int,
    val t: Int,
    val p: Int,
)

public val DEFAULT_KDF_PARAMS: KdfParams = KdfParams(m = 65_536, t = 3, p = 1)

private const val M_MIN = 65_536L
private const val M_MAX = 262_144L
private const val T_MIN = 3L
private const val T_MAX = 16L

/** A JSON number that is an integer (`65536` or `65536.0`, never `65536.5`). */
private fun integerOf(value: Any?): Long? {
    val p = value as? JsonPrimitive ?: return null
    if (p.isString) return null
    p.content.toLongOrNull()?.let { return it }
    val d = p.content.toDoubleOrNull() ?: return null
    if (d.isNaN() || d.isInfinite() || d != Math.floor(d) || Math.abs(d) > 9.007199254740991E15) return null
    return d.toLong()
}

/**
 * Validates prelogin KDF parameters before running the KDF (spec/crypto.md §3, D-005).
 * Rejects downgrades by a malicious server and absurd values that would DoS the client.
 */
public fun validateKdfParams(
    alg: String,
    params: JsonObject,
    salt: ByteArray,
): KdfParams {
    if (alg != KDF_ALG) throw CryptoException(CryptoErrorCode.KDF_PARAMS_REJECTED)
    val m = integerOf(params["m"])
    val t = integerOf(params["t"])
    val p = integerOf(params["p"])
    if (m == null || t == null || p == null || m !in M_MIN..M_MAX || t !in T_MIN..T_MAX || p != 1L) {
        throw CryptoException(CryptoErrorCode.KDF_PARAMS_REJECTED)
    }
    if (salt.size != KDF_SALT_BYTES) throw CryptoException(CryptoErrorCode.KDF_PARAMS_REJECTED)
    return KdfParams(m.toInt(), t.toInt(), p.toInt())
}

public fun validateKdfParams(
    alg: String,
    params: KdfParams,
    salt: ByteArray,
): KdfParams =
    validateKdfParams(
        alg,
        JsonObject(mapOf("m" to JsonPrimitive(params.m), "t" to JsonPrimitive(params.t), "p" to JsonPrimitive(params.p))),
        salt,
    )

/** spec/crypto.md §2: UTF8(NFKC(pw)), no trimming, no case folding. */
public fun normalizePassword(password: String): ByteArray = utf8(Normalizer.normalize(password, Normalizer.Form.NFKC))

/** Raw Argon2id v1.3 (no parameter policy). Prefer [deriveMasterKey]. */
public fun argon2idRaw(
    password: ByteArray,
    salt: ByteArray,
    params: KdfParams,
    length: Int = KEY_BYTES,
): ByteArray {
    val parameters =
        Argon2Parameters
            .Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(params.m)
            .withIterations(params.t)
            .withParallelism(params.p)
            .build()
    val generator = Argon2BytesGenerator()
    generator.init(parameters)
    val out = ByteArray(length)
    generator.generateBytes(password, out)
    return out
}

/** masterKey = Argon2id(NFKC(password), salt, params) after validating params (spec/crypto.md §3–4). */
public fun deriveMasterKey(
    password: String,
    salt: ByteArray,
    params: KdfParams,
    alg: String = KDF_ALG,
): ByteArray {
    val validated = validateKdfParams(alg, params, salt)
    val pw = normalizePassword(password)
    try {
        return argon2idRaw(pw, salt, validated)
    } finally {
        wipe(pw)
    }
}

/** HKDF-SHA256 with empty salt (spec/crypto.md §4, D-002). */
public fun hkdfSha256(
    ikm: ByteArray,
    info: String,
    length: Int = KEY_BYTES,
): ByteArray {
    val generator = HKDFBytesGenerator(SHA256Digest())
    generator.init(HKDFParameters(ikm, null, utf8(info)))
    val out = ByteArray(length)
    generator.generateBytes(out, 0, length)
    return out
}

/** HKDF straight into an AES key; the intermediate bytes are wiped. */
public fun hkdfToAesKey(
    ikm: ByteArray,
    info: String,
): SecretKey {
    val raw = hkdfSha256(ikm, info)
    try {
        return aesKey(raw)
    } finally {
        wipe(raw)
    }
}

public class DerivedLoginKeys(
    /** sent to the server; wipe after use */
    public val authKey: ByteArray,
    /** wraps / unwraps the vault key */
    public val kek: SecretKey,
)

/** password → masterKey → {authKey, kek}; masterKey is wiped. */
public fun deriveLoginKeys(
    password: String,
    salt: ByteArray,
    params: KdfParams,
    alg: String = KDF_ALG,
): DerivedLoginKeys {
    val masterKey = deriveMasterKey(password, salt, params, alg)
    try {
        return DerivedLoginKeys(hkdfSha256(masterKey, INFO_AUTH), hkdfToAesKey(masterKey, INFO_KEK))
    } finally {
        wipe(masterKey)
    }
}

/** spec/crypto.md §2 */
public fun normalizeEmail(email: String): String = Normalizer.normalize(email.jsTrim(), Normalizer.Form.NFKC).lowercase()
