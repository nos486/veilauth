import { type DBSchema, type IDBPDatabase, openDB } from "idb";
import type { ItemKind } from "@zk2fa/crypto";
import type { WireKdf } from "../crypto/protocol";

/**
 * Offline cache in IndexedDB. It holds exactly what the server holds: ids, revisions and
 * ciphertext envelopes. Plaintext never touches disk (build spec §6).
 */
export interface StoredSession {
  userId: string;
  email: string;
  deviceId: string;
  /** null after the server ended the session: the user must log in again (cache is kept) */
  refreshToken: string | null;
  kdf: WireKdf;
  wrappedVaultKey: string;
}

export interface CachedItem {
  id: string;
  kind: ItemKind;
  blob: string | null;
  revision: number;
  deleted: boolean;
  updatedAt: number;
}

export interface PendingChange {
  id: string;
  kind: ItemKind;
  /** null = delete */
  blob: string | null;
  /** server revision this change was made on top of; 0 for a new item */
  baseRevision: number;
  /** increases on every local edit so a push result can tell if the change moved on meanwhile */
  seq: number;
}

interface VaultDb extends DBSchema {
  meta: { key: string; value: unknown };
  items: { key: string; value: CachedItem };
  pending: { key: string; value: PendingChange };
}

export class LocalStore {
  private constructor(private readonly db: IDBPDatabase<VaultDb>) {}

  static async open(name = "veilauth"): Promise<LocalStore> {
    const db = await openDB<VaultDb>(name, 1, {
      upgrade(d) {
        d.createObjectStore("meta");
        d.createObjectStore("items", { keyPath: "id" });
        d.createObjectStore("pending", { keyPath: "id" });
      },
    });
    return new LocalStore(db);
  }

  close(): void {
    this.db.close();
  }

  async getSession(): Promise<StoredSession | null> {
    return ((await this.db.get("meta", "session")) as StoredSession | undefined) ?? null;
  }

  async setSession(session: StoredSession): Promise<void> {
    await this.db.put("meta", session, "session");
  }

  async updateSession(patch: Partial<StoredSession>): Promise<void> {
    const tx = this.db.transaction("meta", "readwrite");
    const current = (await tx.store.get("session")) as StoredSession | undefined;
    if (current) await tx.store.put({ ...current, ...patch }, "session");
    await tx.done;
  }

  async getRevision(): Promise<number> {
    const v = await this.db.get("meta", "revision");
    return typeof v === "number" ? v : 0;
  }

  async allItems(): Promise<CachedItem[]> {
    return this.db.getAll("items");
  }

  async getItem(id: string): Promise<CachedItem | undefined> {
    return this.db.get("items", id);
  }

  /**
   * Applies a pull: upserts server items (or replaces everything on a full resync) and the
   * revision. An item older than the copy we already have is a rollback by the server
   * (docs/THREAT_MODEL.md): it is ignored and counted so the UI can warn.
   */
  async applyPull(
    items: CachedItem[],
    revision: number,
    full: boolean,
  ): Promise<{ rollbacks: number }> {
    const tx = this.db.transaction(["items", "meta"], "readwrite");
    const store = tx.objectStore("items");
    const known = new Map((await store.getAll()).map((i) => [i.id, i.revision]));
    if (full) {
      // Replace the cache: drop everything the server no longer lists.
      const incoming = new Set(items.map((i) => i.id));
      for (const id of known.keys()) if (!incoming.has(id)) await store.delete(id);
    }
    let rollbacks = 0;
    for (const item of items) {
      const seen = known.get(item.id);
      if (seen !== undefined && item.revision < seen) {
        rollbacks++;
        continue;
      }
      if (item.deleted) await store.delete(item.id);
      else await store.put(item);
    }
    await tx.objectStore("meta").put(revision, "revision");
    await tx.done;
    return { rollbacks };
  }

  async allPending(): Promise<PendingChange[]> {
    return this.db.getAll("pending");
  }

  /** Records a local edit. Repeated edits of one item collapse into one change on the same base. */
  async queueChange(change: Omit<PendingChange, "baseRevision" | "seq">): Promise<void> {
    const tx = this.db.transaction(["pending", "items"], "readwrite");
    const existing = await tx.objectStore("pending").get(change.id);
    const cached = await tx.objectStore("items").get(change.id);
    const baseRevision = existing?.baseRevision ?? cached?.revision ?? 0;
    if (existing && existing.baseRevision === 0 && change.blob === null) {
      // Created and deleted before the server ever saw it.
      await tx.objectStore("pending").delete(change.id);
    } else {
      await tx.objectStore("pending").put({
        ...change,
        baseRevision,
        seq: (existing?.seq ?? 0) + 1,
      });
    }
    await tx.done;
  }

  /** Replaces a pending change wholesale (conflict resolution). */
  async putPending(change: PendingChange): Promise<void> {
    await this.db.put("pending", change);
  }

  async dropPending(id: string): Promise<void> {
    await this.db.delete("pending", id);
  }

  /** Marks pushed changes applied, unless they were edited again while the push was in flight. */
  async markApplied(
    applied: { id: string; revision: number; seq: number; change: PendingChange }[],
    revision: number,
  ): Promise<void> {
    const tx = this.db.transaction(["pending", "items", "meta"], "readwrite");
    const pending = tx.objectStore("pending");
    const items = tx.objectStore("items");
    for (const a of applied) {
      if (a.change.blob === null) await items.delete(a.id);
      else
        await items.put({
          id: a.id,
          kind: a.change.kind,
          blob: a.change.blob,
          revision: a.revision,
          deleted: false,
          updatedAt: Date.now(),
        });
      const current = await pending.get(a.id);
      if (current?.seq === a.seq) await pending.delete(a.id);
      else if (current) await pending.put({ ...current, baseRevision: a.revision });
    }
    const stored = await tx.objectStore("meta").get("revision");
    const prev = typeof stored === "number" ? stored : 0;
    // Only advance if nothing else happened in between; otherwise the next pull fills the gap.
    if (revision === prev + 1) await tx.objectStore("meta").put(revision, "revision");
    await tx.done;
  }

  /** Forgets everything (logout, revoked session, account deletion). */
  async wipe(): Promise<void> {
    const tx = this.db.transaction(["meta", "items", "pending"], "readwrite");
    await Promise.all([
      tx.objectStore("meta").clear(),
      tx.objectStore("items").clear(),
      tx.objectStore("pending").clear(),
      tx.done,
    ]);
  }
}
