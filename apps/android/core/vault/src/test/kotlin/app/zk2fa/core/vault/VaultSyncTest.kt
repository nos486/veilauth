package app.zk2fa.core.vault

import app.zk2fa.core.api.PushChange
import app.zk2fa.core.api.PushConflict
import app.zk2fa.core.api.PushConflictReason
import app.zk2fa.core.api.PushResponse
import app.zk2fa.core.api.PushResponseAppliedItem
import app.zk2fa.core.api.SyncResponse
import app.zk2fa.core.api.VaultItem
import app.zk2fa.core.crypto.ItemKind
import app.zk2fa.core.crypto.randomBytes
import app.zk2fa.core.otp.OtpAlgorithm
import app.zk2fa.core.otp.OtpParams
import app.zk2fa.core.otp.OtpType
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Mirrors the server's push rules (apps/worker) like apps/web/test/fake-server.ts. */
class FakeVaultServer : SyncApi {
    var revision = 0L
    val items = LinkedHashMap<String, VaultItem>()

    override suspend fun sync(since: Long): SyncResponse =
        SyncResponse(revision, full = since > revision, items = items.values.filter { it.revision > since }.sortedBy { it.revision })

    override suspend fun push(changes: List<PushChange>): PushResponse {
        val conflicts = ArrayList<PushConflict>()
        val accepted = ArrayList<PushChange>()
        for (ch in changes) {
            val ex = items[ch.id]
            when {
                ex != null && ex.kind != ch.kind -> conflicts.add(PushConflict(ch.id, PushConflictReason.KIND_MISMATCH, ex))
                (ex?.revision ?: 0L) != ch.baseRevision -> conflicts.add(PushConflict(ch.id, PushConflictReason.REVISION_MISMATCH, ex))
                else -> accepted.add(ch)
            }
        }
        if (accepted.isEmpty()) return PushResponse(revision, emptyList(), conflicts)
        val next = ++revision
        for (ch in accepted) items[ch.id] = VaultItem(ch.id, ch.kind, ch.blob, next, ch.blob == null, 0)
        return PushResponse(next, accepted.map { PushResponseAppliedItem(it.id, next) }, conflicts)
    }
}

class VaultSyncTest {
    private val userId = "0192d5f0-6a3c-7c1e-8b2a-3f4e5d6c7b8a"
    private val key = VaultKey.of(userId, randomBytes(32))
    private val server = FakeVaultServer()

    private inner class Device {
        val store = MemoryVaultStore()
        var unlocked = true
        val vault = Vault(store, key)
        val engine = SyncEngine(server, store) { if (unlocked) key else null }
    }

    private fun params(
        account: String,
        type: OtpType = OtpType.TOTP,
    ) = OtpParams(type, "Example", account, "JBSWY3DPEHPK3PXP", OtpAlgorithm.SHA1, 6, 30, 0)

    @Test
    fun `a token added on one device reaches the other and only ciphertext is uploaded`() =
        runTest {
            val a = Device()
            val b = Device()
            a.vault.add(params("alice"))
            a.engine.sync()
            b.engine.sync()
            assertEquals(listOf("alice"), b.vault.tokens().map { it.token.account })
            val blob = server.items.values.single().blob.orEmpty()
            assertTrue(!blob.contains("JBSWY3DPEHPK3PXP") && !blob.contains("alice"))
            assertEquals(0, a.store.allPending().size)
        }

    @Test
    fun `concurrent edits keep both versions`() =
        runTest {
            val a = Device()
            val b = Device()
            a.vault.add(params("alice"))
            a.engine.sync()
            b.engine.sync()
            val onA = a.vault.tokens().single()
            val onB = b.vault.tokens().single()
            a.vault.save(onA.id, onA.token.copy(notes = "from a"))
            b.vault.save(onB.id, onB.token.copy(notes = "from b"))
            a.engine.sync()
            val result = b.engine.sync()
            assertEquals(1, result.conflicts)
            a.engine.sync()
            val accounts = a.vault.tokens().map { it.token.account }.sorted()
            assertEquals(listOf("alice", "alice$CONFLICT_SUFFIX"), accounts)
            assertEquals(b.vault.tokens().map { it.token }.toSet(), a.vault.tokens().map { it.token }.toSet())
        }

    @Test
    fun `HOTP conflicts keep the higher counter and an edit beats a delete`() =
        runTest {
            val a = Device()
            val b = Device()
            a.vault.add(params("hotp", OtpType.HOTP))
            a.engine.sync()
            b.engine.sync()
            a.vault.advanceHotp(a.vault.tokens().single())
            val onB = b.vault.tokens().single()
            b.vault.advanceHotp(b.vault.advanceHotp(onB).let { onB.copy(token = it) })
            a.engine.sync()
            b.engine.sync()
            a.engine.sync()
            assertEquals(listOf(2L), a.vault.tokens().map { it.token.counter })

            a.vault.deleteForever(a.vault.tokens().single().id)
            val again = b.vault.tokens().single()
            b.vault.save(again.id, again.token.copy(notes = "kept"))
            b.engine.sync()
            a.engine.sync()
            assertEquals(listOf("kept"), a.vault.tokens().map { it.token.notes })
        }

    @Test
    fun `conflicts that need the key wait until the vault is unlocked`() =
        runTest {
            val a = Device()
            val b = Device()
            a.vault.add(params("alice"))
            a.engine.sync()
            b.engine.sync()
            a.vault.save(a.vault.tokens().single().id, a.vault.tokens().single().token.copy(notes = "a"))
            b.vault.save(b.vault.tokens().single().id, b.vault.tokens().single().token.copy(notes = "b"))
            a.engine.sync()
            b.unlocked = false
            assertEquals(1, b.engine.sync().deferred)
            assertEquals(1, b.store.allPending().size)
            b.unlocked = true
            assertEquals(1, b.engine.sync().conflicts)
            assertEquals(2, b.vault.tokens().size)
        }

    @Test
    fun `server rollbacks are ignored and counted`() =
        runTest {
            val a = Device()
            a.vault.add(params("alice"))
            a.engine.sync()
            val item = server.items.values.single()
            a.store.applyPull(listOf(item.copy(revision = item.revision + 5).toCached()), server.revision, full = false)
            val rollbacks = a.store.applyPull(listOf(item.toCached()), server.revision, full = false)
            assertEquals(1, rollbacks)
        }

    @Test
    fun `a full resync drops items the server no longer has but keeps local edits`() =
        runTest {
            val a = Device()
            a.vault.add(params("alice"))
            a.engine.sync()
            a.vault.add(params("bob"))
            a.store.applyPull(emptyList(), 0, full = true)
            assertEquals(listOf("bob"), a.vault.tokens().map { it.token.account })
        }

    @Test
    fun `trash and restore round-trip`() =
        runTest {
            val a = Device()
            a.vault.add(params("alice"))
            a.vault.moveToTrash(a.vault.tokens().single())
            assertTrue(a.vault.tokens().single().token.trashedAt != null)
            a.vault.restore(a.vault.tokens().single())
            assertEquals(null, a.vault.tokens().single().token.trashedAt)
            assertEquals(ItemKind.TOKEN, a.store.allPending().single().kind)
        }

    @Test
    fun `uuid v7 is valid for the AAD`() {
        repeat(100) { app.zk2fa.core.crypto.assertId(uuidV7()) }
    }
}
