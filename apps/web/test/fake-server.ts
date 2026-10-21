import type { PushChange, PushConflict, VaultItem } from "@zk2fa/shared";

/** In-memory model of /sync and /sync/push with the Worker's semantics (apps/worker/src/routes/sync.ts). */
export class FakeVaultServer {
  revision = 0;
  readonly items = new Map<string, VaultItem>();

  readonly fetch: typeof fetch = (input, init) => Promise.resolve(this.route(input, init));

  private route(input: string | URL | Request, init: RequestInit | undefined): Response {
    const url = new URL(
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url,
      "http://x",
    );
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
    if (url.pathname === "/api/v1/sync" && init?.method === "GET") {
      const since = Number(url.searchParams.get("since") ?? "0");
      const items = [...this.items.values()]
        .filter((i) => i.revision > since)
        .sort((a, b) => a.revision - b.revision);
      return json(200, { revision: this.revision, full: since > this.revision, items });
    }
    if (url.pathname === "/api/v1/sync/push" && init?.method === "POST") {
      const { changes } = JSON.parse(init.body as string) as { changes: PushChange[] };
      return json(200, this.push(changes));
    }
    if (url.pathname === "/api/v1/time") return json(200, { now: Date.now() });
    return json(404, { code: "NOT_FOUND", message: "Not found." });
  }

  push(changes: PushChange[]) {
    const conflicts: PushConflict[] = [];
    const accepted: PushChange[] = [];
    for (const ch of changes) {
      const ex = this.items.get(ch.id);
      if (ex && ex.kind !== ch.kind)
        conflicts.push({ id: ch.id, reason: "kind_mismatch", server: ex });
      else if ((ex?.revision ?? 0) !== ch.baseRevision)
        conflicts.push({ id: ch.id, reason: "revision_mismatch", server: ex ?? null });
      else accepted.push(ch);
    }
    if (accepted.length === 0) return { revision: this.revision, applied: [], conflicts };
    const next = ++this.revision;
    for (const ch of accepted) {
      this.items.set(ch.id, {
        id: ch.id,
        kind: ch.kind,
        blob: ch.blob,
        revision: next,
        deleted: ch.blob === null,
        updatedAt: Date.now(),
      });
    }
    return {
      revision: next,
      applied: accepted.map((ch) => ({ id: ch.id, revision: next })),
      conflicts,
    };
  }
}
