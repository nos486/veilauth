import { LIMITS } from "@zk2fa/shared";
import { and, eq, lt, sql } from "drizzle-orm";
import type { DrizzleD1Database } from "drizzle-orm/d1";
import { auditLog, counters, devices, refreshHistory, users, vaultItems } from "./db/schema.js";
import type * as schema from "./db/schema.js";

const REVOKED_DEVICE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

/** Daily maintenance (build spec §5.3–5.4): tombstone purge, audit retention, expired auth state. */
export async function runMaintenance(
  db: DrizzleD1Database<typeof schema>,
  now: number,
): Promise<void> {
  const tombstoneCutoff = now - LIMITS.tombstoneRetentionMs;
  await db.batch([
    // Raise each user's horizon to the highest revision about to be purged, then purge.
    db
      .update(users)
      .set({
        tombstoneHorizon: sql`MAX(${users.tombstoneHorizon}, (SELECT MAX(${vaultItems.revision}) FROM ${vaultItems} WHERE ${vaultItems.userId} = ${users.id} AND ${vaultItems.deleted} = 1 AND ${vaultItems.updatedAt} < ${tombstoneCutoff}))`,
      })
      .where(
        sql`EXISTS (SELECT 1 FROM ${vaultItems} WHERE ${vaultItems.userId} = ${users.id} AND ${vaultItems.deleted} = 1 AND ${vaultItems.updatedAt} < ${tombstoneCutoff})`,
      ),
    db
      .delete(vaultItems)
      .where(and(eq(vaultItems.deleted, true), lt(vaultItems.updatedAt, tombstoneCutoff))),
    db.delete(auditLog).where(lt(auditLog.createdAt, now - LIMITS.auditRetentionMs)),
    db.delete(refreshHistory).where(lt(refreshHistory.expiresAt, now)),
    db.delete(counters).where(and(lt(counters.expiresAt, now), lt(counters.lockedUntil, now))),
    db
      .delete(devices)
      .where(
        sql`(${devices.revokedAt} IS NOT NULL AND ${devices.revokedAt} < ${now - REVOKED_DEVICE_RETENTION_MS}) OR ${devices.refreshExpiresAt} < ${now - REVOKED_DEVICE_RETENTION_MS}`,
      ),
  ]);
}
