package app.zk2fa.core.vault

import app.zk2fa.core.api.ApiClient
import app.zk2fa.core.api.ApiException
import app.zk2fa.core.api.PushChange
import app.zk2fa.core.api.PushConflict
import app.zk2fa.core.api.PushConflictReason
import app.zk2fa.core.api.PushResponse
import app.zk2fa.core.api.SyncResponse
import app.zk2fa.core.api.VaultItem
import app.zk2fa.core.crypto.ItemKind
import app.zk2fa.core.crypto.validateTokenItem
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import app.zk2fa.core.api.ItemKind as WireKind

/** The two sync endpoints; [ApiClient] in the app, a fake server in tests. */
public interface SyncApi {
    public suspend fun sync(since: Long): SyncResponse

    public suspend fun push(changes: List<PushChange>): PushResponse
}

public fun ApiClient.asSyncApi(): SyncApi {
    val api = this
    return object : SyncApi {
        override suspend fun sync(since: Long): SyncResponse = api.sync(since)

        override suspend fun push(changes: List<PushChange>): PushResponse = api.push(changes)
    }
}

public data class SyncResult(
    /** conflicts that were reconciled (copies or merges) */
    val conflicts: Int,
    /** conflicts left for later because they need the vault key and the vault is locked */
    val deferred: Int,
    /** items the server tried to roll back to an older revision (ignored) */
    val rollbacks: Int,
    val revision: Long,
)

internal fun ItemKind.toWire(): WireKind =
    when (this) {
        ItemKind.TOKEN -> WireKind.TOKEN
        ItemKind.FOLDER -> WireKind.FOLDER
        ItemKind.SETTINGS -> WireKind.SETTINGS
    }

internal fun WireKind.toKind(): ItemKind =
    when (this) {
        WireKind.TOKEN -> ItemKind.TOKEN
        WireKind.FOLDER -> ItemKind.FOLDER
        WireKind.SETTINGS -> ItemKind.SETTINGS
    }

internal fun VaultItem.toCached(): CachedItem = CachedItem(id, kind.toKind(), blob, revision, deleted, updatedAt)

private const val MAX_ROUNDS = 4
private const val MAX_CHANGES_PER_PUSH = 200

/**
 * Pull-then-push sync against /sync and /sync/push (build spec §5.3), the same algorithm as
 * apps/web/src/sync/engine.ts. Local edits are queued in the store first, so the app works
 * offline and nothing is lost if a push fails. It runs without the vault key (in the background
 * worker): conflicts that need decryption are then left queued until the next unlocked sync.
 */
public class SyncEngine(
    private val api: SyncApi,
    private val store: VaultStore,
    private val key: () -> VaultKey?,
) {
    private val mutex = Mutex()

    public suspend fun sync(): SyncResult = mutex.withLock { run() }

    private suspend fun run(): SyncResult {
        var conflicts = 0
        var rollbacks = 0
        val deferred = HashSet<String>()
        suspend fun pull(): Long {
            val res = api.sync(store.getRevision())
            rollbacks += store.applyPull(res.items.map { it.toCached() }, res.revision, res.full)
            return res.revision
        }

        var revision = pull()
        for (round in 0 until MAX_ROUNDS) {
            val batch = store.allPending().filter { it.id !in deferred }.take(MAX_CHANGES_PER_PUSH)
            if (batch.isEmpty()) break
            val res =
                try {
                    api.push(batch.map { PushChange(it.id, it.kind.toWire(), it.blob, it.baseRevision) })
                } catch (e: ApiException) {
                    if (e.code != "SYNC_RETRY") throw e
                    revision = pull()
                    continue
                }
            val byId = batch.associateBy { it.id }
            store.markApplied(res.applied.mapNotNull { a -> byId[a.id]?.let { AppliedChange(a.id, a.revision, it) } }, res.revision)
            for (c in res.conflicts) {
                val local = byId[c.id] ?: continue
                when (resolve(c, local)) {
                    Outcome.RESOLVED -> conflicts++
                    Outcome.DEFERRED -> deferred.add(c.id)
                }
            }
            // Pull whatever other devices pushed meanwhile, and the server copies of conflicted items.
            revision = pull()
        }
        return SyncResult(conflicts, deferred.size, rollbacks, revision)
    }

    private enum class Outcome { RESOLVED, DEFERRED }

    private suspend fun resolve(
        conflict: PushConflict,
        local: PendingChange,
    ): Outcome {
        val server = conflict.server
        val serverBlob = server?.blob

        if (conflict.reason == PushConflictReason.KIND_MISMATCH) {
            // Id collision with a different kind: keep ours under a fresh id.
            val localBlob = local.blob
            if (localBlob == null) {
                store.dropPending(local.id)
                return Outcome.RESOLVED
            }
            val k = key() ?: return Outcome.DEFERRED
            store.dropPending(local.id)
            val mine = k.decrypt(local.id, local.kind, localBlob) ?: return Outcome.RESOLVED
            val id = uuidV7()
            store.queueChange(id, local.kind, k.encrypt(id, local.kind, mine))
            return Outcome.RESOLVED
        }

        if (local.blob == null) {
            // Local delete vs remote edit: the remote edit wins, so the token survives.
            store.dropPending(local.id)
            return Outcome.RESOLVED
        }

        if (server == null || server.deleted || serverBlob == null) {
            // Deleted (or purged) on the server but edited here: bring it back.
            store.replacePending(local.copy(baseRevision = server?.revision ?: 0L))
            return Outcome.RESOLVED
        }

        if (local.kind != ItemKind.TOKEN) {
            // Folders and settings: the server copy wins.
            store.dropPending(local.id)
            return Outcome.RESOLVED
        }

        val k = key() ?: return Outcome.DEFERRED
        val mine = k.decrypt(local.id, ItemKind.TOKEN, local.blob)?.let(::validTokenOrNull)
        val theirs = k.decrypt(server.id, ItemKind.TOKEN, serverBlob)?.let(::validTokenOrNull)
        if (mine == null) {
            store.dropPending(local.id)
            return Outcome.RESOLVED
        }
        if (theirs == null) {
            // The server copy is unreadable; keep ours on top of it rather than losing it.
            store.replacePending(local.copy(baseRevision = server.revision))
            return Outcome.RESOLVED
        }
        when (val decision = resolveTokenConflict(mine, theirs)) {
            TokenResolution.Same -> store.dropPending(local.id)
            is TokenResolution.Merge ->
                store.replacePending(
                    local.copy(blob = k.encrypt(local.id, ItemKind.TOKEN, decision.value.toJson()), baseRevision = server.revision),
                )
            is TokenResolution.Copy -> {
                store.dropPending(local.id)
                val id = uuidV7()
                store.queueChange(id, ItemKind.TOKEN, k.encrypt(id, ItemKind.TOKEN, decision.value.toJson()))
            }
        }
        return Outcome.RESOLVED
    }
}

internal fun validTokenOrNull(value: kotlinx.serialization.json.JsonElement) =
    try {
        validateTokenItem(value)
    } catch (_: app.zk2fa.core.crypto.CryptoException) {
        null
    }
