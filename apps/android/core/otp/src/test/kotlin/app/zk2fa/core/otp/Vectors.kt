package app.zk2fa.core.otp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File

/** spec/test-vectors.json → `otp` section. */
internal object Vectors {
    val otp: JsonObject by lazy {
        val dir = System.getProperty("veilauth.specDir") ?: error("veilauth.specDir is not set")
        Json.parseToJsonElement(File(dir, "test-vectors.json").readText()).jsonObject.getValue("otp").jsonObject
    }

    fun section(name: String): List<JsonObject> = otp.getValue(name).jsonArray.map { it.jsonObject }
}

internal fun JsonObject.str(key: String): String = getValue(key).jsonPrimitive.content

internal fun JsonObject.int(key: String): Int = getValue(key).jsonPrimitive.int

internal fun JsonObject.long(key: String): Long = getValue(key).jsonPrimitive.long

internal fun JsonObject.array(key: String): JsonArray = getValue(key).jsonArray

internal fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

internal fun JsonElement.toParams(): OtpParams {
    val o = jsonObject
    return OtpParams(
        type = OtpType.fromWireName(o.str("type")) ?: error("type"),
        issuer = o.str("issuer"),
        account = o.str("account"),
        secret = o.str("secret"),
        algorithm = OtpAlgorithm.valueOf(o.str("algorithm")),
        digits = o.int("digits"),
        period = o.int("period"),
        counter = o.long("counter"),
    )
}

internal fun JsonElement.toMigrationEntry(): MigrationEntry {
    val o = jsonObject
    return if (o.getValue("ok").jsonPrimitive.content == "true") {
        MigrationEntry.Ok(o.getValue("value").toParams())
    } else {
        MigrationEntry.Failed(OtpErrorCode.valueOf(o.str("error")), o.str("issuer"), o.str("account"))
    }
}
