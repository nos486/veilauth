import { isWellFormedEnvelope } from "@zk2fa/crypto/server";
import {
  LIMITS,
  type PushConflict,
  PushRequest,
  type PushResponse,
  SyncQuery,
  type SyncResponse,
  type VaultItem,
} from "@zk2fa/shared";
import { and, count, eq, gt, inArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import type { AppEnv } from "../app-env.js";
import { users, vaultItems, type VaultItemRow } from "../db/schema.js";
import { requireAuth } from "../lib/auth.js";
import { ApiError } from "../lib/errors.js";
import { body, parse } from "../lib/request.js";

export const sync = new Hono<AppEnv>();
sync.use(requireAuth);

const MAX_ATTEMPTS = 5;
const ID_CHUNK = 90;

function toApi(row: VaultItemRow): VaultItem {
  return {
    id: row.id,
    kind: row.kind,
    blob: row.blob,
    revision: row.revision,
    deleted: row.deleted,
    updatedAt: row.updatedAt,
  };
}

sync.get("/", async (c) => {
  const { since } = parse(SyncQuery, c.req.query());
  const db = c.get("db");
  const { userId } = c.get("auth");
  const user = await db
    .select({ revision: users.vaultRevision, horizon: users.tombstoneHorizon })
    .from(users)
    .where(eq(users.id, userId))
    .get();
  if (user === undefined) throw new ApiError("SESSION_REVOKED");
  // Tombstones at or below the horizon were purged: an older client must replace its cache.
  const full = since > user.revision || (since > 0 && since < user.horizon);
  const rows = await db
    .select()
    .from(vaultItems)
    .where(
      full
        ? eq(vaultItems.userId, userId)
        : and(eq(vaultItems.userId, userId), gt(vaultItems.revision, since)),
    )
    .orderBy(vaultItems.revision)
    .all();
  const res: SyncResponse = {
    revision: user.revision,
    full: full || since === 0,
    items: rows.map(toApi),
  };
  return c.json(res);
});

/** Thrown when a concurrent push changed vault_revision between our read and our write. */
function isRevisionRace(e: unknown): boolean {
  const text = e instanceof Error ? `${e.message} ${String(e.cause)}` : "";
  return text.includes("NOT NULL constraint failed: users.vault_revision");
}

sync.post("/push", async (c) => {
  const req = await body(c, PushRequest);
  const db = c.get("db");
  const { userId } = c.get("auth");

  const ids = req.changes.map((ch) => ch.id);
  if (new Set(ids).size !== ids.length)
    throw new ApiError("BAD_REQUEST", { detail: "Duplicate item ids in push." });
  for (const ch of req.changes) {
    if (ch.blob !== null && !isWellFormedEnvelope(ch.blob, { padded: true })) {
      throw new ApiError("BAD_REQUEST", { detail: "Invalid fields: changes.blob" });
    }
  }

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const now = Date.now();
    const user = await db
      .select({ revision: users.vaultRevision })
      .from(users)
      .where(eq(users.id, userId))
      .get();
    if (user === undefined) throw new ApiError("SESSION_REVOKED");
    const existing = new Map<string, VaultItemRow>();
    // D1 allows at most 100 bound parameters per query.
    for (let i = 0; i < ids.length; i += ID_CHUNK) {
      const rows = await db
        .select()
        .from(vaultItems)
        .where(inArray(vaultItems.id, ids.slice(i, i + ID_CHUNK)))
        .all();
      for (const r of rows) existing.set(r.id, r);
    }

    const conflicts: PushConflict[] = [];
    const accepted: typeof req.changes = [];
    let liveDelta = 0;
    for (const ch of req.changes) {
      const ex = existing.get(ch.id);
      if (ex !== undefined && ex.userId !== userId) throw new ApiError("ID_TAKEN");
      if (ex !== undefined && ex.kind !== ch.kind) {
        conflicts.push({ id: ch.id, reason: "kind_mismatch", server: toApi(ex) });
      } else if ((ex?.revision ?? 0) !== ch.baseRevision) {
        conflicts.push({
          id: ch.id,
          reason: "revision_mismatch",
          server: ex === undefined ? null : toApi(ex),
        });
      } else {
        accepted.push(ch);
        const wasLive = ex !== undefined && !ex.deleted;
        const isLive = ch.blob !== null;
        liveDelta += Number(isLive) - Number(wasLive);
      }
    }

    if (accepted.length === 0) {
      const res: PushResponse = { revision: user.revision, applied: [], conflicts };
      return c.json(res);
    }

    if (liveDelta > 0) {
      const live = await db
        .select({ n: count() })
        .from(vaultItems)
        .where(and(eq(vaultItems.userId, userId), eq(vaultItems.deleted, false)))
        .get();
      if ((live?.n ?? 0) + liveDelta > LIMITS.maxItemsPerUser) throw new ApiError("VAULT_LIMIT");
    }

    const next = user.revision + 1;
    // First statement aborts the whole batch (NOT NULL violation) if another push won the race (D-022).
    const guard = db
      .update(users)
      .set({
        vaultRevision: sql`CASE WHEN ${users.vaultRevision} = ${user.revision} THEN ${next} ELSE NULL END`,
        updatedAt: now,
      })
      .where(eq(users.id, userId));
    const writes = accepted.map((ch) =>
      db
        .insert(vaultItems)
        .values({
          id: ch.id,
          userId,
          kind: ch.kind,
          blob: ch.blob,
          revision: next,
          deleted: ch.blob === null,
          updatedAt: now,
        })
        .onConflictDoUpdate({
          target: vaultItems.id,
          set: { blob: ch.blob, revision: next, deleted: ch.blob === null, updatedAt: now },
          setWhere: sql`${vaultItems.userId} = ${userId}`,
        }),
    );
    try {
      await db.batch([guard, ...writes]);
    } catch (e: unknown) {
      if (isRevisionRace(e)) {
        // Jittered backoff so contending pushes from the same account spread out.
        await new Promise((resolve) => setTimeout(resolve, Math.random() * 15 * (attempt + 1)));
        continue;
      }
      throw e;
    }
    const res: PushResponse = {
      revision: next,
      applied: accepted.map((ch) => ({ id: ch.id, revision: next })),
      conflicts,
    };
    return c.json(res);
  }
  throw new ApiError("SYNC_RETRY");
});
