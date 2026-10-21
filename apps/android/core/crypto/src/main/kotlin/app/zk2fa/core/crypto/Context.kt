package app.zk2fa.core.crypto

private val UUID_V7 = Regex("[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")

public enum class ItemKind(public val wireName: String) {
    TOKEN("token"),
    FOLDER("folder"),
    SETTINGS("settings"),
    ;

    public companion object {
        public fun fromWireName(name: String): ItemKind? = entries.firstOrNull { it.wireName == name }
    }
}

public fun assertId(id: String) {
    if (!UUID_V7.matches(id)) throw CryptoException(CryptoErrorCode.INVALID_CONTEXT, "id must be a lowercase UUIDv7")
}

/** AAD contexts (spec/crypto.md §5). Every component is validated so "|" cannot be injected. */
public object Ctx {
    public fun vaultKey(userId: String): String {
        assertId(userId)
        return "zk2fa/v1/vk|$userId"
    }

    public fun recoveryVaultKey(userId: String): String {
        assertId(userId)
        return "zk2fa/v1/rvk|$userId"
    }

    public fun item(
        userId: String,
        itemId: String,
        kind: ItemKind,
    ): String {
        assertId(userId)
        assertId(itemId)
        return "zk2fa/v1/item|$userId|$itemId|${kind.wireName}"
    }

    public fun device(
        userId: String,
        deviceId: String,
    ): String {
        assertId(userId)
        assertId(deviceId)
        return "zk2fa/v1/device|$userId|$deviceId"
    }
}
