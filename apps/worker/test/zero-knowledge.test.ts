import { describe, expect, it } from "vitest";
import { call, env, TestClient, uuidv7 } from "./helpers.js";

/**
 * Zero-knowledge audit (build spec §8.1): after realistic traffic, dump every D1 table and assert that
 * no plaintext token data appears anywhere. The Phase 2 E2E suite repeats this against a real browser run.
 */
describe("zero-knowledge audit", () => {
  it("stores no plaintext issuer, account, secret, notes or key material", async () => {
    const client = new TestClient("zk-audit@example.com");
    await client.register();
    const plaintext = {
      type: "totp",
      issuer: "ZkAuditIssuerCorp",
      account: "zk.audit.account@example.org",
      secret: "KRUGS4ZANFZSA5DPOAQHGZLDOJSXIIJB", // gitleaks:allow (public test value)
      algorithm: "SHA256",
      digits: 8,
      period: 30,
      counter: 0,
      iconId: "zkauditicon",
      folderId: null,
      tags: ["zkaudittag"],
      notes: "zk audit private note",
      favorite: true,
      createdAt: 1760000000000,
      trashedAt: null,
    };
    const id = uuidv7();
    const folderId = uuidv7();
    await call("/api/v1/sync/push", {
      token: client.token,
      body: {
        changes: [
          { id, kind: "token", blob: await client.blob(id, plaintext), baseRevision: 0 },
          {
            id: folderId,
            kind: "folder",
            blob: await client.blob(folderId, { name: "ZkAuditFolder", createdAt: 1 }, "folder"),
            baseRevision: 0,
          },
        ],
      },
    });
    await client.login(uuidv7());

    const tables = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_cf%' ESCAPE '\\' AND name NOT LIKE 'sqlite%' AND name NOT LIKE 'd1_%'",
    ).all<{ name: string }>();
    let dump = "";
    for (const { name } of tables.results) {
      const rows = await env.DB.prepare(`SELECT * FROM "${name}"`).all();
      dump += JSON.stringify(rows.results, (_k, v: unknown) =>
        v instanceof ArrayBuffer ? [...new Uint8Array(v)] : v,
      );
    }
    expect(dump).toContain(client.userId); // sanity: the dump has data
    const forbidden = [
      plaintext.issuer,
      plaintext.account,
      plaintext.secret,
      plaintext.notes,
      plaintext.iconId,
      "zkaudittag",
      "ZkAuditFolder",
      client.authKey,
      client.recoveryAuth,
      "198.51.", // raw client IPs
    ];
    for (const needle of forbidden)
      expect(dump.toLowerCase(), needle).not.toContain(needle.toLowerCase());
  });
});
