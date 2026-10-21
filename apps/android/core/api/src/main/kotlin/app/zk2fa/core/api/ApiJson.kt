package app.zk2fa.core.api

import kotlinx.serialization.json.Json

/**
 * JSON settings for the veilauth API: unknown response keys are ignored (the server may add
 * fields), optional request fields left at their `null` default are omitted, and required
 * nullable fields are always sent.
 */
public val ApiJson: Json =
    Json {
        ignoreUnknownKeys = true
        encodeDefaults = false
        explicitNulls = true
    }
