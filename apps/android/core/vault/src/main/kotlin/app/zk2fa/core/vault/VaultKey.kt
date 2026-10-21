package app.zk2fa.core.vault

import app.zk2fa.core.crypto.CryptoException
import app.zk2fa.core.crypto.ItemKind
import app.zk2fa.core.crypto.ItemRef
import app.zk2fa.core.crypto.aesKey
import app.zk2fa.core.crypto.decryptItem
import app.zk2fa.core.crypto.encryptItem
import kotlinx.serialization.json.JsonElement
import javax.crypto.SecretKey

/** The unlocked vault key of one account. Held in memory only while the vault is unlocked. */
public class VaultKey private constructor(
    public val userId: String,
    private val key: SecretKey,
) {
    /** Returns null when the blob does not decrypt or parse (it is skipped, never shown half-read). */
    public fun decrypt(
        id: String,
        kind: ItemKind,
        blob: String,
    ): JsonElement? =
        try {
            decryptItem(key, ItemRef(userId, id, kind), blob)
        } catch (_: CryptoException) {
            null
        }

    public fun encrypt(
        id: String,
        kind: ItemKind,
        value: JsonElement,
    ): String = encryptItem(key, ItemRef(userId, id, kind), value)

    override fun toString(): String = "VaultKey(userId=$userId)"

    public companion object {
        /** Copies `raw` into a key object; the caller wipes `raw`. */
        public fun of(
            userId: String,
            raw: ByteArray,
        ): VaultKey = VaultKey(userId, aesKey(raw))
    }
}
