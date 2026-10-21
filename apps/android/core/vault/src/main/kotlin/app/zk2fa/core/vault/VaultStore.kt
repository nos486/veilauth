package app.zk2fa.core.vault

import app.zk2fa.core.crypto.ItemKind
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** One server item as cached on the device: ids, revisions and ciphertext only. */
public data class CachedItem(
    val id: String,
    val kind: ItemKind,
    val blob: String?,
    val revision: Long,
    val deleted: Boolean,
    val updatedAt: Long,
)

public data class PendingChange(
    val id: String,
    val kind: ItemKind,
    /** null = delete */
    val blob: String?,
    /** server revision this change was made on top of; 0 for a new item */
    val baseRevision: Long,
    /** increases on every local edit so a push result can tell if the change moved on meanwhile */
    val seq: Long,
)

public data class AppliedChange(
    val id: String,
    val revision: Long,
    val change: PendingChange,
)

/** Storage primitives, all called inside [VaultStore.transaction]. */
public interface VaultTx {
    public suspend fun item(id: String): CachedItem?

    public suspend fun allItems(): List<CachedItem>

    public suspend fun putItem(item: CachedItem)

    public suspend fun deleteItem(id: String)

    public suspend fun pending(id: String): PendingChange?

    public suspend fun allPending(): List<PendingChange>

    public suspend fun putPending(change: PendingChange)

    public suspend fun deletePending(id: String)

    public suspend fun revision(): Long

    public suspend fun setRevision(revision: Long)

    public suspend fun clear()
}

/**
 * Offline cache with the same semantics as the web client's IndexedDB store
 * (apps/web/src/store/db.ts). It holds exactly what the server holds: ids, revisions and
 * ciphertext envelopes. Plaintext never touches disk.
 */
public abstract class VaultStore(
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val _version = MutableStateFlow(0L)

    /** Bumped after every write, so screens know when to re-read. */
    public val version: StateFlow<Long> = _version.asStateFlow()

    protected abstract suspend fun <T> transaction(block: suspend VaultTx.() -> T): T

    private suspend fun <T> write(block: suspend VaultTx.() -> T): T = transaction(block).also { _version.value++ }

    public suspend fun getRevision(): Long = transaction { revision() }

    public suspend fun allItems(): List<CachedItem> = transaction { allItems() }

    public suspend fun allPending(): List<PendingChange> = transaction { allPending() }

    /**
     * Applies a pull: upserts server items (or replaces everything on a full resync) and the
     * revision. An item older than the copy we already have is a rollback by the server
     * (docs/THREAT_MODEL.md): it is ignored and counted so the UI can warn.
     */
    public suspend fun applyPull(
        items: List<CachedItem>,
        revision: Long,
        full: Boolean,
    ): Int =
        write {
            val known = allItems().associate { it.id to it.revision }
            if (full) {
                val incoming = items.mapTo(HashSet()) { it.id }
                for (id in known.keys) if (id !in incoming) deleteItem(id)
            }
            var rollbacks = 0
            for (item in items) {
                val seen = known[item.id]
                if (seen != null && item.revision < seen) {
                    rollbacks++
                    continue
                }
                if (item.deleted) deleteItem(item.id) else putItem(item)
            }
            setRevision(revision)
            rollbacks
        }

    /** Records a local edit. Repeated edits of one item collapse into one change on the same base. */
    public suspend fun queueChange(
        id: String,
        kind: ItemKind,
        blob: String?,
    ): Unit =
        write {
            val existing = pending(id)
            val baseRevision = existing?.baseRevision ?: item(id)?.revision ?: 0L
            if (existing != null && existing.baseRevision == 0L && blob == null) {
                // Created and deleted before the server ever saw it.
                deletePending(id)
            } else {
                putPending(PendingChange(id, kind, blob, baseRevision, (existing?.seq ?: 0L) + 1))
            }
        }

    /** Replaces a pending change wholesale (conflict resolution). */
    public suspend fun replacePending(change: PendingChange): Unit = write { putPending(change) }

    public suspend fun dropPending(id: String): Unit = write { deletePending(id) }

    /** Marks pushed changes applied, unless they were edited again while the push was in flight. */
    public suspend fun markApplied(
        applied: List<AppliedChange>,
        revision: Long,
    ): Unit =
        write {
            for (a in applied) {
                if (a.change.blob == null) {
                    deleteItem(a.id)
                } else {
                    putItem(CachedItem(a.id, a.change.kind, a.change.blob, a.revision, deleted = false, updatedAt = clock()))
                }
                val current = pending(a.id)
                if (current?.seq == a.change.seq) {
                    deletePending(a.id)
                } else if (current != null) {
                    putPending(current.copy(baseRevision = a.revision))
                }
            }
            // Only advance if nothing else happened in between; otherwise the next pull fills the gap.
            if (revision == revision() + 1) setRevision(revision)
        }

    /** Forgets everything (logout, revoked session, account switch). */
    public suspend fun wipe(): Unit = write { clear() }
}

/** In-memory store with a single lock; used by tests and as the reference for the Room store. */
public class MemoryVaultStore(
    clock: () -> Long = System::currentTimeMillis,
) : VaultStore(clock) {
    private val items = LinkedHashMap<String, CachedItem>()
    private val pending = LinkedHashMap<String, PendingChange>()
    private var revision = 0L
    private val lock = kotlinx.coroutines.sync.Mutex()

    private val tx =
        object : VaultTx {
            override suspend fun item(id: String) = items[id]

            override suspend fun allItems() = items.values.toList()

            override suspend fun putItem(item: CachedItem) {
                items[item.id] = item
            }

            override suspend fun deleteItem(id: String) {
                items.remove(id)
            }

            override suspend fun pending(id: String) = pending[id]

            override suspend fun allPending() = pending.values.toList()

            override suspend fun putPending(change: PendingChange) {
                pending[change.id] = change
            }

            override suspend fun deletePending(id: String) {
                pending.remove(id)
            }

            override suspend fun revision() = revision

            override suspend fun setRevision(revision: Long) {
                this@MemoryVaultStore.revision = revision
            }

            override suspend fun clear() {
                items.clear()
                pending.clear()
                revision = 0
            }
        }

    override suspend fun <T> transaction(block: suspend VaultTx.() -> T): T {
        lock.lock()
        try {
            return tx.block()
        } finally {
            lock.unlock()
        }
    }
}
