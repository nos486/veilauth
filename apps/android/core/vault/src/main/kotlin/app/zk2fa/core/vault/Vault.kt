package app.zk2fa.core.vault

import app.zk2fa.core.crypto.ItemKind
import app.zk2fa.core.crypto.TokenItem
import app.zk2fa.core.otp.OtpParams

/** A decrypted token with its item id. */
public data class VaultToken(
    val id: String,
    val token: TokenItem,
    /** edited locally and not yet accepted by the server */
    val pending: Boolean,
)

public fun newTokenItem(
    params: OtpParams,
    now: Long,
): TokenItem =
    TokenItem(
        type = params.type.wireName,
        issuer = params.issuer.take(256),
        account = params.account.take(256),
        secret = params.secret,
        algorithm = params.algorithm.name,
        digits = params.digits,
        period = params.period,
        counter = params.counter,
        iconId = null,
        folderId = null,
        tags = emptyList(),
        notes = "",
        favorite = false,
        createdAt = now,
        trashedAt = null,
    )

/** Decrypted view of the vault plus local edits. Every edit is encrypted before it is stored. */
public class Vault(
    private val store: VaultStore,
    private val key: VaultKey,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    /** Live tokens (pending edits win over the cached server copy); undecryptable blobs are skipped. */
    public suspend fun tokens(): List<VaultToken> {
        val pending = store.allPending().associateBy { it.id }
        val out = ArrayList<VaultToken>()
        for (item in store.allItems()) {
            if (item.kind != ItemKind.TOKEN || item.id in pending) continue
            val blob = item.blob ?: continue
            decryptToken(item.id, blob)?.let { out.add(VaultToken(item.id, it, pending = false)) }
        }
        for (change in pending.values) {
            if (change.kind != ItemKind.TOKEN) continue
            val blob = change.blob ?: continue
            decryptToken(change.id, blob)?.let { out.add(VaultToken(change.id, it, pending = true)) }
        }
        return out.sortedWith(compareByDescending<VaultToken> { it.token.favorite }.thenBy { it.token.issuer.lowercase() }.thenBy { it.token.account.lowercase() })
    }

    private fun decryptToken(
        id: String,
        blob: String,
    ): TokenItem? = key.decrypt(id, ItemKind.TOKEN, blob)?.let(::validTokenOrNull)

    public suspend fun add(params: OtpParams): String {
        val id = uuidV7(clock())
        save(id, newTokenItem(params, clock()))
        return id
    }

    public suspend fun save(
        id: String,
        token: TokenItem,
    ) {
        store.queueChange(id, ItemKind.TOKEN, key.encrypt(id, ItemKind.TOKEN, token.toJson()))
    }

    public suspend fun moveToTrash(entry: VaultToken): Unit = save(entry.id, entry.token.copy(trashedAt = clock()))

    public suspend fun restore(entry: VaultToken): Unit = save(entry.id, entry.token.copy(trashedAt = null))

    public suspend fun deleteForever(id: String): Unit = store.queueChange(id, ItemKind.TOKEN, null)

    /** HOTP: advance the counter and save, so the next code is shown (same as the web app). */
    public suspend fun advanceHotp(entry: VaultToken): TokenItem {
        val next = entry.token.copy(counter = entry.token.counter + 1)
        save(entry.id, next)
        return next
    }
}
