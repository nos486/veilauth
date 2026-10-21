import { LIMITS, type PushConflict, type PushChange } from "@zk2fa/shared";
import { ApiError, type ApiClient } from "../api/client";
import type { CryptoClient } from "../crypto/client";
import type { PlainValue } from "../crypto/protocol";
import { uuidv7 } from "../lib/uuid";
import type { LocalStore, PendingChange } from "../store/db";
import { resolveTokenConflict } from "./conflicts";

export interface SyncResult {
  /** number of conflicts that were reconciled (copies or merges) */
  conflicts: number;
  /** items the server tried to roll back to an older revision (ignored) */
  rollbacks: number;
  revision: number;
}

const MAX_ROUNDS = 4;

/**
 * Pull-then-push sync against /sync and /sync/push (build spec §5.3). Local edits are queued in
 * IndexedDB first, so the app works offline and nothing is lost if a push fails.
 */
export class SyncEngine {
  private running: Promise<SyncResult> | null = null;
  private rollbacks = 0;

  constructor(
    private readonly api: ApiClient,
    private readonly store: LocalStore,
    private readonly crypto: CryptoClient,
    private readonly userId: string,
  ) {}

  /** Runs one sync; concurrent callers share the same run. */
  sync(): Promise<SyncResult> {
    this.running ??= this.run().finally(() => {
      this.running = null;
    });
    return this.running;
  }

  private async run(): Promise<SyncResult> {
    let conflicts = 0;
    this.rollbacks = 0;
    let revision = await this.pull();
    for (let round = 0; round < MAX_ROUNDS; round++) {
      const pending = await this.store.allPending();
      if (pending.length === 0) break;
      const batch = pending.slice(0, LIMITS.maxChangesPerPush);
      const changes: PushChange[] = batch.map((p) => ({
        id: p.id,
        kind: p.kind,
        blob: p.blob,
        baseRevision: p.baseRevision,
      }));
      let res;
      try {
        res = await this.api.push(changes);
      } catch (e: unknown) {
        if (e instanceof ApiError && e.code === "SYNC_RETRY") {
          revision = await this.pull();
          continue;
        }
        throw e;
      }
      const byId = new Map(batch.map((p) => [p.id, p]));
      await this.store.markApplied(
        res.applied.flatMap((a) => {
          const change = byId.get(a.id);
          return change ? [{ id: a.id, revision: a.revision, seq: change.seq, change }] : [];
        }),
        res.revision,
      );
      for (const c of res.conflicts) {
        const local = byId.get(c.id);
        if (local) {
          await this.resolve(c, local);
          conflicts++;
        }
      }
      // Pull whatever other devices pushed meanwhile, and the server copies of conflicted items.
      revision = await this.pull();
    }
    return { conflicts, revision, rollbacks: this.rollbacks };
  }

  private async pull(): Promise<number> {
    const since = await this.store.getRevision();
    const res = await this.api.sync(since);
    const { rollbacks } = await this.store.applyPull(res.items, res.revision, res.full);
    this.rollbacks += rollbacks;
    return res.revision;
  }

  private async decryptOne(id: string, kind: PendingChange["kind"], blob: string) {
    const [r] = await this.crypto.call("decrypt", {
      userId: this.userId,
      items: [{ id, kind, blob }],
    });
    return r?.ok === true ? r : null;
  }

  private async encryptOne(id: string, plain: PlainValue): Promise<string> {
    const [r] = await this.crypto.call("encrypt", {
      userId: this.userId,
      items: [{ id, ...plain }],
    });
    if (!r) throw new Error("encrypt returned nothing");
    return r.blob;
  }

  private async resolve(conflict: PushConflict, local: PendingChange): Promise<void> {
    const server = conflict.server;
    const serverLive = server !== null && !server.deleted && server.blob !== null;

    if (conflict.reason === "kind_mismatch") {
      // Id collision with a different kind: keep ours under a fresh id.
      await this.store.dropPending(local.id);
      if (local.blob === null) return;
      const mine = await this.decryptOne(local.id, local.kind, local.blob);
      if (!mine) return;
      const id = uuidv7();
      await this.store.queueChange({ id, kind: local.kind, blob: await this.encryptOne(id, mine) });
      return;
    }

    if (local.blob === null) {
      // Local delete vs remote edit: the remote edit wins, so the token survives.
      await this.store.dropPending(local.id);
      return;
    }

    if (!serverLive) {
      // Deleted (or purged) on the server but edited here: bring it back.
      await this.store.putPending({ ...local, baseRevision: server?.revision ?? 0 });
      return;
    }

    if (local.kind !== "token") {
      // Folders and settings: the server copy wins.
      await this.store.dropPending(local.id);
      return;
    }

    const mine = await this.decryptOne(local.id, "token", local.blob);
    const theirs = await this.decryptOne(server.id, "token", server.blob ?? "");
    if (mine?.kind !== "token") {
      await this.store.dropPending(local.id);
      return;
    }
    if (theirs?.kind !== "token") {
      // The server copy is unreadable; keep ours on top of it rather than losing it.
      await this.store.putPending({ ...local, baseRevision: server.revision });
      return;
    }
    const decision = resolveTokenConflict(mine.value, theirs.value);
    switch (decision.action) {
      case "same":
        await this.store.dropPending(local.id);
        return;
      case "merge":
        await this.store.putPending({
          ...local,
          blob: await this.encryptOne(local.id, { kind: "token", value: decision.value }),
          baseRevision: server.revision,
        });
        return;
      case "copy": {
        await this.store.dropPending(local.id);
        const id = uuidv7();
        await this.store.queueChange({
          id,
          kind: "token",
          blob: await this.encryptOne(id, { kind: "token", value: decision.value }),
        });
        return;
      }
    }
  }
}
