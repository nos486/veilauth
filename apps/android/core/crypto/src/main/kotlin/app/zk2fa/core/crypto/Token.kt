package app.zk2fa.core.crypto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Decrypted token plaintext (spec/crypto.md §6.3). */
public data class TokenItem(
    val type: String,
    val issuer: String,
    val account: String,
    val secret: String,
    val algorithm: String,
    val digits: Int,
    val period: Int,
    val counter: Long,
    val iconId: String?,
    val folderId: String?,
    val tags: List<String>,
    val notes: String,
    val favorite: Boolean,
    val createdAt: Long,
    val trashedAt: Long?,
    /** unknown keys are preserved for forward compatibility (D-008) */
    val extra: Map<String, JsonElement> = emptyMap(),
) {
    public fun toJson(): JsonObject =
        JsonObject(
            extra +
                mapOf(
                    "type" to JsonPrimitive(type),
                    "issuer" to JsonPrimitive(issuer),
                    "account" to JsonPrimitive(account),
                    "secret" to JsonPrimitive(secret),
                    "algorithm" to JsonPrimitive(algorithm),
                    "digits" to JsonPrimitive(digits),
                    "period" to JsonPrimitive(period),
                    "counter" to JsonPrimitive(counter),
                    "iconId" to JsonPrimitive(iconId),
                    "folderId" to JsonPrimitive(folderId),
                    "tags" to JsonArray(tags.map(::JsonPrimitive)),
                    "notes" to JsonPrimitive(notes),
                    "favorite" to JsonPrimitive(favorite),
                    "createdAt" to JsonPrimitive(createdAt),
                    "trashedAt" to JsonPrimitive(trashedAt),
                ),
        )

    override fun toString(): String = "TokenItem(type=$type, issuer=$issuer, account=$account, secret=<redacted>)"

    public companion object {
        internal val KEYS: Set<String> =
            setOf(
                "type", "issuer", "account", "secret", "algorithm", "digits", "period", "counter", "iconId",
                "folderId", "tags", "notes", "favorite", "createdAt", "trashedAt",
            )
    }
}

public data class FolderItem(
    val name: String,
    val createdAt: Long,
    val extra: Map<String, JsonElement> = emptyMap(),
) {
    public fun toJson(): JsonObject =
        JsonObject(extra + mapOf("name" to JsonPrimitive(name), "createdAt" to JsonPrimitive(createdAt)))
}

private val BASE32 = Regex("[A-Z2-7]+")

private fun fail(field: String): Nothing = throw CryptoException(CryptoErrorCode.INVALID_ITEM, "invalid field: $field")

private fun str(
    v: JsonElement?,
    field: String,
    max: Int,
): String {
    if (v !is JsonPrimitive || !v.isString || v.content.length > max) fail(field)
    return v.content
}

private fun int(
    v: JsonElement?,
    field: String,
    min: Long,
    max: Long,
): Long {
    if (v !is JsonPrimitive) fail(field)
    val n = safeIntegerOf(v) ?: fail(field)
    if (n < min || n > max) fail(field)
    return n
}

private fun nullableStr(
    v: JsonElement?,
    field: String,
    max: Int,
): String? = if (v is JsonNull) null else str(v, field, max)

private fun obj(v: JsonElement): JsonObject = v as? JsonObject ?: fail("<root>")

/** Validates a decrypted token plaintext against spec/crypto.md §6.3. */
public fun validateTokenItem(value: JsonElement): TokenItem {
    val o = obj(value)
    val type = (o["type"] as? JsonPrimitive)?.takeIf { it.isString }?.content
    if (type != "totp" && type != "hotp" && type != "steam") fail("type")
    val algorithm = (o["algorithm"] as? JsonPrimitive)?.takeIf { it.isString }?.content
    if (algorithm != "SHA1" && algorithm != "SHA256" && algorithm != "SHA512") fail("algorithm")
    if (type == "steam" && algorithm != "SHA1") fail("algorithm")
    val secret = str(o["secret"], "secret", 205)
    val secretBytes = secret.length * 5 / 8
    if (!BASE32.matches(secret) || secretBytes < 1 || secretBytes > 128) fail("secret")
    val digits = if (type == "steam") int(o["digits"], "digits", 5, 5) else int(o["digits"], "digits", 6, 8)
    val tags = o["tags"]
    if (tags !is JsonArray || tags.size > 32) fail("tags")
    val favorite = o["favorite"]
    if (favorite !is JsonPrimitive || favorite.isString || (favorite.content != "true" && favorite.content != "false")) fail("favorite")
    val trashedAt = o["trashedAt"]
    return TokenItem(
        type = type,
        issuer = str(o["issuer"], "issuer", 256),
        account = str(o["account"], "account", 256),
        secret = secret,
        algorithm = algorithm,
        digits = digits.toInt(),
        period = int(o["period"], "period", 1, 86_400).toInt(),
        counter = int(o["counter"], "counter", 0, MAX_SAFE_INTEGER),
        iconId = nullableStr(o["iconId"], "iconId", 128),
        folderId = nullableStr(o["folderId"], "folderId", 36),
        tags = tags.map { str(it, "tags", 64) },
        notes = str(o["notes"], "notes", 2048),
        favorite = favorite.content == "true",
        createdAt = int(o["createdAt"], "createdAt", 0, MAX_SAFE_INTEGER),
        trashedAt = if (trashedAt is JsonNull) null else int(trashedAt, "trashedAt", 0, MAX_SAFE_INTEGER),
        extra = o.filterKeys { it !in TokenItem.KEYS },
    )
}

public fun validateFolderItem(value: JsonElement): FolderItem {
    val o = obj(value)
    return FolderItem(
        name = str(o["name"], "name", 128),
        createdAt = int(o["createdAt"], "createdAt", 0, MAX_SAFE_INTEGER),
        extra = o.filterKeys { it != "name" && it != "createdAt" },
    )
}
