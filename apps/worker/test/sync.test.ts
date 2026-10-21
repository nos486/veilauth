import type { PushResponse, SyncResponse } from "@zk2fa/shared";
import { decryptItem, toBase64Url } from "@zk2fa/crypto";
import { describe, expect, it } from "vitest";
import { call, expectError, fakeBlob, json, TestClient, uuidv7 } from "./helpers.js";

async function push(client: TestClient, changes: unknown[]): Promise<Response> {
  return call("/api/v1/sync/push", { token: client.token, body: { changes } });
}

async function pull(client: TestClient, since = 0): Promise<SyncResponse> {
  return json<SyncResponse>(await call(`/api/v1/sync?since=${since}`, { token: client.token }));
}

const token = {
  type: "totp",
  issuer: "GitHub",
  account: "alice@example.com",
  secret: "JBSWY3DPEHPK3PXP",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  counter: 0,
  iconId: null,
  folderId: null,
  tags: [],
  notes: "",
  favorite: false,
  createdAt: 1760000000000,
  trashedAt: null,
};

describe("sync", () => {
  it("pushes, pulls and round-trips real ciphertext", async () => {
    const client = new TestClient();
    await client.register();
    const id = uuidv7();
    const res = await json<PushResponse>(
      await push(client, [
        { id, kind: "token", blob: await client.blob(id, token), baseRevision: 0 },
      ]),
    );
    expect(res).toMatchObject({ revision: 1, applied: [{ id, revision: 1 }], conflicts: [] });

    const all = await pull(client);
    expect(all.revision).toBe(1);
    expect(all.full).toBe(true);
    const item = all.items[0];
    if (item?.blob == null) throw new Error("missing item");
    expect(
      await decryptItem(
        await client.vaultKey(),
        { userId: client.userId, itemId: id, kind: "token" },
        item.blob,
      ),
    ).toEqual(token);
    expect((await pull(client, 1)).items).toEqual([]);
  });

  it("returns only newer items, including tombstones", async () => {
    const client = new TestClient();
    await client.register();
    const [a, b] = [uuidv7(), uuidv7()];
    await push(client, [
      { id: a, kind: "token", blob: fakeBlob(), baseRevision: 0 },
      { id: b, kind: "folder", blob: fakeBlob(), baseRevision: 0 },
    ]);
    const del = await json<PushResponse>(
      await push(client, [{ id: a, kind: "token", blob: null, baseRevision: 1 }]),
    );
    expect(del.revision).toBe(2);
    const delta = await pull(client, 1);
    expect(delta.full).toBe(false);
    expect(delta.items).toEqual([
      expect.objectContaining({ id: a, blob: null, deleted: true, revision: 2 }),
    ]);
  });

  it("reports a conflict with the server copy when baseRevision is stale", async () => {
    const client = new TestClient();
    await client.register();
    const id = uuidv7();
    const v1 = fakeBlob();
    await push(client, [{ id, kind: "token", blob: v1, baseRevision: 0 }]);
    await push(client, [{ id, kind: "token", blob: fakeBlob(), baseRevision: 1 }]);
    const stale = await json<PushResponse>(
      await push(client, [{ id, kind: "token", blob: fakeBlob(), baseRevision: 1 }]),
    );
    expect(stale.applied).toEqual([]);
    expect(stale.conflicts).toEqual([
      {
        id,
        reason: "revision_mismatch",
        server: expect.objectContaining({ id, revision: 2 }) as unknown,
      },
    ]);
    const kind = await json<PushResponse>(
      await push(client, [{ id, kind: "folder", blob: fakeBlob(), baseRevision: 2 }]),
    );
    expect(kind.conflicts[0]?.reason).toBe("kind_mismatch");
  });

  it("applies non-conflicting changes in the same push", async () => {
    const client = new TestClient();
    await client.register();
    const [a, b] = [uuidv7(), uuidv7()];
    await push(client, [{ id: a, kind: "token", blob: fakeBlob(), baseRevision: 0 }]);
    const res = await json<PushResponse>(
      await push(client, [
        { id: a, kind: "token", blob: fakeBlob(), baseRevision: 0 },
        { id: b, kind: "token", blob: fakeBlob(), baseRevision: 0 },
      ]),
    );
    expect(res.applied).toEqual([{ id: b, revision: 2 }]);
    expect(res.conflicts.map((c) => c.id)).toEqual([a]);
  });

  it("serialises concurrent pushes without losing either", async () => {
    const client = new TestClient();
    await client.register();
    // A client retries on SYNC_RETRY; the server already retries internally with backoff.
    const pushWithRetry = async (): Promise<PushResponse> => {
      const change = { id: uuidv7(), kind: "token", blob: fakeBlob(), baseRevision: 0 };
      for (;;) {
        const res = await push(client, [change]);
        if (res.status === 200) return json<PushResponse>(res);
        await expectError(res, 409, "SYNC_RETRY");
      }
    };
    const revisions = (await Promise.all(Array.from({ length: 4 }, pushWithRetry))).map(
      (r) => r.revision,
    );
    expect(new Set(revisions).size).toBe(4);
    const all = await pull(client);
    expect(all.items).toHaveLength(4);
    expect(new Set(all.items.map((i) => i.revision)).size).toBe(4);
  });

  it("rejects writes to another user's item id", async () => {
    const a = new TestClient();
    await a.register();
    const b = new TestClient();
    await b.register();
    const id = uuidv7();
    await push(a, [{ id, kind: "token", blob: fakeBlob(), baseRevision: 0 }]);
    await expectError(
      await push(b, [{ id, kind: "token", blob: fakeBlob(), baseRevision: 1 }]),
      409,
      "ID_TAKEN",
    );
    expect((await pull(b)).items).toEqual([]);
  });

  it.each([
    [
      "unpadded blob",
      () => toBase64Url(Uint8Array.from({ length: 100 }, (_, i) => (i === 0 ? 1 : i))),
    ],
    ["wrong version", () => `B${fakeBlob().slice(1)}`],
    ["oversized blob", () => fakeBlob(24)],
  ])("rejects a malformed envelope (%s)", async (_n, blob) => {
    const client = new TestClient();
    await client.register();
    await expectError(
      await push(client, [{ id: uuidv7(), kind: "token", blob: blob(), baseRevision: 0 }]),
      400,
      "BAD_REQUEST",
    );
  });

  it("rejects duplicate ids and more than 200 changes", async () => {
    const client = new TestClient();
    await client.register();
    const id = uuidv7();
    const change = { id, kind: "token", blob: fakeBlob(), baseRevision: 0 };
    await expectError(await push(client, [change, change]), 400, "BAD_REQUEST");
    const many = Array.from({ length: 201 }, () => ({ ...change, id: uuidv7() }));
    await expectError(await push(client, many), 400, "BAD_REQUEST");
  });

  it("caps a vault at 1000 live items", async () => {
    const client = new TestClient();
    await client.register();
    const blob = fakeBlob();
    for (let i = 0; i < 5; i++) {
      const res = await push(
        client,
        Array.from({ length: 200 }, () => ({ id: uuidv7(), kind: "token", blob, baseRevision: 0 })),
      );
      expect(res.status).toBe(200);
    }
    await expectError(
      await push(client, [{ id: uuidv7(), kind: "token", blob, baseRevision: 0 }]),
      409,
      "VAULT_LIMIT",
    );
  });

  it("requires authentication", async () => {
    await expectError(await call("/api/v1/sync"), 401, "UNAUTHORIZED");
  });
});
