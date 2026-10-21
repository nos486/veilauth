package app.zk2fa.data

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.withTransaction
import app.zk2fa.core.crypto.ItemKind
import app.zk2fa.core.vault.CachedItem
import app.zk2fa.core.vault.PendingChange
import app.zk2fa.core.vault.VaultStore
import app.zk2fa.core.vault.VaultTx

/** Ciphertext cache (build spec §6): the same columns the server stores, nothing decrypted. */
@Entity(tableName = "items")
data class ItemEntity(
    @PrimaryKey val id: String,
    val kind: String,
    val blob: String?,
    val revision: Long,
    val deleted: Boolean,
    val updatedAt: Long,
)

@Entity(tableName = "pending")
data class PendingEntity(
    @PrimaryKey val id: String,
    val kind: String,
    val blob: String?,
    val baseRevision: Long,
    val seq: Long,
)

@Entity(tableName = "meta")
data class MetaEntity(
    @PrimaryKey val key: String,
    val value: Long,
)

@Dao
interface VaultDao {
    @Query("SELECT * FROM items WHERE id = :id")
    suspend fun item(id: String): ItemEntity?

    @Query("SELECT * FROM items")
    suspend fun allItems(): List<ItemEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun putItem(item: ItemEntity)

    @Query("DELETE FROM items WHERE id = :id")
    suspend fun deleteItem(id: String)

    @Query("SELECT * FROM pending WHERE id = :id")
    suspend fun pending(id: String): PendingEntity?

    @Query("SELECT * FROM pending ORDER BY seq")
    suspend fun allPending(): List<PendingEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun putPending(change: PendingEntity)

    @Query("DELETE FROM pending WHERE id = :id")
    suspend fun deletePending(id: String)

    @Query("SELECT value FROM meta WHERE `key` = 'revision'")
    suspend fun revision(): Long?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun putMeta(meta: MetaEntity)

    @Query("DELETE FROM items")
    suspend fun clearItems()

    @Query("DELETE FROM pending")
    suspend fun clearPending()

    @Query("DELETE FROM meta")
    suspend fun clearMeta()
}

@Database(entities = [ItemEntity::class, PendingEntity::class, MetaEntity::class], version = 1, exportSchema = false)
abstract class VaultDatabase : RoomDatabase() {
    abstract fun dao(): VaultDao

    companion object {
        fun open(context: Context): VaultDatabase = Room.databaseBuilder(context, VaultDatabase::class.java, "vault.db").build()
    }
}

private fun kindOf(wire: String): ItemKind = ItemKind.fromWireName(wire) ?: error("unknown item kind in the local cache")

private fun ItemEntity.toModel() = CachedItem(id, kindOf(kind), blob, revision, deleted, updatedAt)

private fun CachedItem.toEntity() = ItemEntity(id, kind.wireName, blob, revision, deleted, updatedAt)

private fun PendingEntity.toModel() = PendingChange(id, kindOf(kind), blob, baseRevision, seq)

private fun PendingChange.toEntity() = PendingEntity(id, kind.wireName, blob, baseRevision, seq)

/** Room-backed [VaultStore]; the merge/conflict rules live in :core:vault and are tested there. */
class RoomVaultStore(
    private val db: VaultDatabase,
) : VaultStore() {
    private val dao = db.dao()

    private val tx =
        object : VaultTx {
            override suspend fun item(id: String) = dao.item(id)?.toModel()

            override suspend fun allItems() = dao.allItems().map { it.toModel() }

            override suspend fun putItem(item: CachedItem) = dao.putItem(item.toEntity())

            override suspend fun deleteItem(id: String) = dao.deleteItem(id)

            override suspend fun pending(id: String) = dao.pending(id)?.toModel()

            override suspend fun allPending() = dao.allPending().map { it.toModel() }

            override suspend fun putPending(change: PendingChange) = dao.putPending(change.toEntity())

            override suspend fun deletePending(id: String) = dao.deletePending(id)

            override suspend fun revision() = dao.revision() ?: 0L

            override suspend fun setRevision(revision: Long) = dao.putMeta(MetaEntity("revision", revision))

            override suspend fun clear() {
                dao.clearItems()
                dao.clearPending()
                dao.clearMeta()
            }
        }

    override suspend fun <T> transaction(block: suspend VaultTx.() -> T): T = db.withTransaction { tx.block() }
}
