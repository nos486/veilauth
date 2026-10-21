import type { TokenItem } from "@zk2fa/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { ApiClient } from "../src/api/client";
import type { RegistrationKeys } from "../src/crypto/protocol";
import { newTokenItem } from "../src/lib/tokens";
import { uuidv7 } from "../src/lib/uuid";
import { LocalStore } from "../src/store/db";
import { SyncEngine } from "../src/sync/engine";
import { CONFLICT_SUFFIX } from "../src/sync/conflicts";
import { DirectCryptoClient, STRONG_PASSWORD } from "./helpers";
import { FakeVaultServer } from "./fake-server";

const base = newTokenItem(
  {
    type: "totp",
    issuer: "Example",
    account: "alice@example.com",
    secret: "JBSWY3DPEHPK3PXP", // gitleaks:allow (public test value)
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    counter: 0,
  },
  1_700_000_000_000,
);

let userId: string;
let reg: RegistrationKeys;

beforeAll(async () => {
  userId = uuidv7();
  reg = await new DirectCryptoClient().call("register", { password: STRONG_PASSWORD, userId });
});

interface Device {
  crypto: DirectCryptoClient;
  store: LocalStore;
  engine: SyncEngine;
  save(id: string, value: TokenItem): Promise<void>;
  remove(id: string): Promise<void>;
  tokens(): Promise<Map<string, TokenItem>>;
}

async function device(server: FakeVaultServer, name: string): Promise<Device> {
  const crypto = new DirectCryptoClient();
  await crypto.call("deriveLogin", { password: STRONG_PASSWORD, kdf: reg.kdf });
  await crypto.call("unlock", { userId, wrappedVaultKey: reg.wrappedVaultKey });
  const store = await LocalStore.open(`${name}-${uuidv7()}`);
  const api = new ApiClient({
    fetch: server.fetch,
    tokens: {
      loadRefreshToken: () => Promise.resolve("x"),
      saveRefreshToken: () => Promise.resolve(),
    },
    onSessionEnded: () => undefined,
    withLock: (_n, fn) => fn(),
  });
  api.setAccessToken("token", Date.now() + 3_600_000);
  const engine = new SyncEngine(api, store, crypto, userId);
  return {
    crypto,
    store,
    engine,
    async save(id, value) {
      const [enc] = await crypto.call("encrypt", { userId, items: [{ id, kind: "token", value }] });
      await store.queueChange({ id, kind: "token", blob: enc?.blob ?? "" });
    },
    async remove(id) {
      await store.queueChange({ id, kind: "token", blob: null });
    },
    async tokens() {
      const items = (await store.allItems()).filter((i) => i.blob !== null);
      const res = await crypto.call("decrypt", {
        userId,
        items: items.map((i) => ({ id: i.id, kind: i.kind, blob: i.blob ?? "" })),
      });
      const out = new Map<string, TokenItem>();
      for (const r of res) if (r.ok && r.kind === "token") out.set(r.id, r.value);
      return out;
    },
  };
}

describe("sync engine", () => {
  it("syncs a new token to a second device, ciphertext only", async () => {
    const server = new FakeVaultServer();
    const a = await device(server, "a");
    const b = await device(server, "b");
    const id = uuidv7();
    await a.save(id, base);
    await a.engine.sync();
    expect(await a.store.allPending()).toEqual([]);
    expect(JSON.stringify([...server.items.values()])).not.toContain("alice");
    await b.engine.sync();
    expect((await b.tokens()).get(id)).toEqual(base);
  });

  it("keeps both versions when two offline devices edit the same token", async () => {
    const server = new FakeVaultServer();
    const a = await device(server, "a");
    const b = await device(server, "b");
    const id = uuidv7();
    await a.save(id, base);
    await a.engine.sync();
    await b.engine.sync();

    // both offline, both edit
    await a.save(id, { ...base, issuer: "Edited on A" });
    await b.save(id, { ...base, issuer: "Edited on B" });
    await a.engine.sync();
    const res = await b.engine.sync();
    expect(res.conflicts).toBe(1);
    await a.engine.sync();

    for (const d of [a, b]) {
      const tokens = [...(await d.tokens()).values()];
      expect(tokens).toHaveLength(2);
      expect(tokens.map((t) => t.issuer).sort()).toEqual(["Edited on A", "Edited on B"]);
      const copy = tokens.find((t) => t.issuer === "Edited on B");
      expect(copy?.account).toBe(base.account + CONFLICT_SUFFIX);
      expect(await d.store.allPending()).toEqual([]);
    }
  });

  it("takes the higher HOTP counter instead of copying", async () => {
    const server = new FakeVaultServer();
    const a = await device(server, "a");
    const b = await device(server, "b");
    const id = uuidv7();
    const hotp: TokenItem = { ...base, type: "hotp", counter: 5 };
    await a.save(id, hotp);
    await a.engine.sync();
    await b.engine.sync();
    await a.save(id, { ...hotp, counter: 9 });
    await b.save(id, { ...hotp, counter: 7 });
    await b.engine.sync();
    await a.engine.sync();
    await b.engine.sync();
    for (const d of [a, b]) {
      const tokens = [...(await d.tokens()).values()];
      expect(tokens).toHaveLength(1);
      expect(tokens[0]?.counter).toBe(9);
    }
  });

  it("never loses a token: a remote edit beats a local delete, a local edit revives a remote delete", async () => {
    const server = new FakeVaultServer();
    const a = await device(server, "a");
    const b = await device(server, "b");
    const one = uuidv7();
    const two = uuidv7();
    await a.save(one, { ...base, issuer: "One" });
    await a.save(two, { ...base, issuer: "Two" });
    await a.engine.sync();
    await b.engine.sync();

    await a.save(one, { ...base, issuer: "One edited" });
    await b.remove(one);
    await a.remove(two);
    await b.save(two, { ...base, issuer: "Two edited" });
    await a.engine.sync();
    await b.engine.sync();
    await a.engine.sync();

    for (const d of [a, b]) {
      const issuers = [...(await d.tokens()).values()].map((t) => t.issuer).sort();
      expect(issuers).toEqual(["One edited", "Two edited"]);
    }
  });

  it("collapses repeated offline edits and drops create-then-delete", async () => {
    const server = new FakeVaultServer();
    const a = await device(server, "a");
    const id = uuidv7();
    await a.save(id, base);
    await a.save(id, { ...base, issuer: "Second" });
    expect(await a.store.allPending()).toHaveLength(1);
    const temp = uuidv7();
    await a.save(temp, base);
    await a.remove(temp);
    expect((await a.store.allPending()).map((p) => p.id)).toEqual([id]);
    await a.engine.sync();
    expect(server.revision).toBe(1);
    expect([...(await a.tokens()).values()].map((t) => t.issuer)).toEqual(["Second"]);
  });
});

describe("rollback protection", () => {
  it("ignores an older revision of an item the device has already seen", async () => {
    const server = new FakeVaultServer();
    const a = await device(server, "a");
    const id = uuidv7();
    await a.save(id, { ...base, issuer: "v1" });
    await a.engine.sync();
    const old = server.items.get(id);
    await a.save(id, { ...base, issuer: "v2" });
    await a.engine.sync();
    // A malicious server replays the old ciphertext with its old revision.
    const cached = await a.store.getItem(id);
    const res = await a.store.applyPull(old ? [old] : [], server.revision, true);
    expect(res.rollbacks).toBe(1);
    expect((await a.store.getItem(id))?.blob).toBe(cached?.blob);
  });
});
