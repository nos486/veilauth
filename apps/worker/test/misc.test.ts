import type { DevicesResponse, SessionResponse } from "@zk2fa/shared";
import { drizzle } from "drizzle-orm/d1";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runMaintenance } from "../src/cron.js";
import * as schema from "../src/db/schema.js";
import type { Env } from "../src/env.js";
import { signAccessToken } from "../src/lib/jwt.js";
import { requireTurnstile } from "../src/lib/turnstile.js";
import { call, env, expectError, fakeBlob, json, TestClient, uuidv7 } from "./helpers.js";

describe("meta endpoints and headers", () => {
  it("serves /time and /config with security headers", async () => {
    const res = await call("/api/v1/time");
    const { now } = await json<{ now: number }>(res);
    expect(Math.abs(now - Date.now())).toBeLessThan(5000);
    for (const h of [
      "content-security-policy",
      "strict-transport-security",
      "x-content-type-options",
      "referrer-policy",
      "permissions-policy",
    ]) {
      expect(res.headers.get(h)).toBeTruthy();
    }
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    const config = await json<{ turnstileSiteKey: string | null }>(await call("/api/v1/config"));
    expect(config.turnstileSiteKey).toBeNull();
  });

  it("answers unknown API paths with a JSON 404", async () => {
    await expectError(await call("/api/v1/nope"), 404, "NOT_FOUND");
    await expectError(await call("/api/v2/time"), 404, "NOT_FOUND");
  });

  it("rejects non-JSON bodies", async () => {
    const res = await call("/api/v1/auth/prelogin", {
      method: "POST",
      headers: { "content-type": "text/plain" },
    });
    await expectError(res, 400, "BAD_REQUEST");
  });
});

describe("access tokens", () => {
  it("rejects tampered and expired tokens", async () => {
    const client = new TestClient();
    const s = await client.register();
    const [h, p, sig] = s.accessToken.split(".");
    const tampered = `${h ?? ""}.${p ?? ""}x.${sig ?? ""}`;
    await expectError(await call("/api/v1/devices", { token: tampered }), 401, "UNAUTHORIZED");
    const none = `${btoa(JSON.stringify({ alg: "none", typ: "JWT" })).replace(/=/g, "")}.${p ?? ""}.`;
    await expectError(await call("/api/v1/devices", { token: none }), 401, "UNAUTHORIZED");
    const past = Math.floor(Date.now() / 1000) - 60;
    const expired = await signAccessToken(env.JWT_PRIVATE_JWK, {
      iss: "veilauth",
      sub: s.userId,
      did: s.deviceId,
      stamp: "x",
      iat: past - 900,
      exp: past,
    });
    await expectError(await call("/api/v1/devices", { token: expired }), 401, "TOKEN_EXPIRED");
  });
});

describe("devices", () => {
  it("lists sessions and revokes another device immediately", async () => {
    const client = new TestClient();
    await client.register();
    const other = await json<SessionResponse>(await client.login(uuidv7()));
    const list = await json<DevicesResponse>(
      await call("/api/v1/devices", { token: client.token }),
    );
    expect(list.devices).toHaveLength(2);
    expect(list.devices.find((d) => d.current)?.id).toBe(client.deviceId);

    expect(
      (await call(`/api/v1/devices/${other.deviceId}`, { method: "DELETE", token: client.token }))
        .status,
    ).toBe(204);
    await expectError(
      await call("/api/v1/devices", { token: other.accessToken }),
      401,
      "SESSION_REVOKED",
    );
    await expectError(
      await call(`/api/v1/devices/${uuidv7()}`, { method: "DELETE", token: client.token }),
      404,
      "NOT_FOUND",
    );
  });

  it("cannot revoke another user's device", async () => {
    const a = new TestClient();
    await a.register();
    const b = new TestClient();
    await b.register();
    await expectError(
      await call(`/api/v1/devices/${b.deviceId}`, { method: "DELETE", token: a.token }),
      404,
      "NOT_FOUND",
    );
  });
});

describe("account deletion", () => {
  it("requires a fresh authKey and removes every row", async () => {
    const client = new TestClient();
    await client.register();
    await call("/api/v1/sync/push", {
      token: client.token,
      body: { changes: [{ id: uuidv7(), kind: "token", blob: fakeBlob(), baseRevision: 0 }] },
    });
    await expectError(
      await call("/api/v1/account", {
        method: "DELETE",
        token: client.token,
        body: { authKey: "A".repeat(43) },
      }),
      401,
      "INVALID_CREDENTIALS",
    );
    const res = await call("/api/v1/account", {
      method: "DELETE",
      token: client.token,
      body: { authKey: client.authKey },
    });
    expect(res.status).toBe(204);
    for (const table of ["users", "devices", "vault_items", "audit_log", "refresh_history"]) {
      const col = table === "users" ? "id" : "user_id";
      const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE ${col} = ?`)
        .bind(client.userId)
        .first<{ n: number }>();
      expect(row?.n, table).toBe(0);
    }
    await expectError(await client.login(), 401, "INVALID_CREDENTIALS");
  });
});

describe("maintenance cron", () => {
  it("purges old tombstones and forces a full resync for stale clients", async () => {
    const client = new TestClient();
    await client.register();
    const [a, b] = [uuidv7(), uuidv7()];
    await call("/api/v1/sync/push", {
      token: client.token,
      body: {
        changes: [
          { id: a, kind: "token", blob: fakeBlob(), baseRevision: 0 },
          { id: b, kind: "token", blob: fakeBlob(), baseRevision: 0 },
        ],
      },
    });
    await call("/api/v1/sync/push", {
      token: client.token,
      body: { changes: [{ id: a, kind: "token", blob: null, baseRevision: 1 }] },
    });
    const ninetyOneDaysAgo = Date.now() - 91 * 24 * 60 * 60 * 1000;
    await env.DB.prepare("UPDATE vault_items SET updated_at = ? WHERE id = ?")
      .bind(ninetyOneDaysAgo, a)
      .run();
    await runMaintenance(drizzle(env.DB, { schema }), Date.now());

    const stale = await json<{ full: boolean; items: { id: string }[] }>(
      await call("/api/v1/sync?since=1", { token: client.token }),
    );
    expect(stale.full).toBe(true);
    expect(stale.items.map((i) => i.id)).toEqual([b]);
    const fresh = await json<{ full: boolean }>(
      await call("/api/v1/sync?since=2", { token: client.token }),
    );
    expect(fresh.full).toBe(false);
  });
});

describe("Turnstile", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const prodEnv = {
    ...env,
    ENVIRONMENT: "production",
    TURNSTILE_SITE_KEY: "site",
    TURNSTILE_SECRET_KEY: "secret",
  } as Env;

  it("requires a token outside development and checks it with siteverify", async () => {
    await expect(requireTurnstile(prodEnv, undefined, "1.2.3.4")).rejects.toMatchObject({
      code: "TURNSTILE_REQUIRED",
    });
    const fetchMock = vi.fn(() => Promise.resolve(Response.json({ success: false })));
    vi.stubGlobal("fetch", fetchMock);
    await expect(requireTurnstile(prodEnv, "tok", "1.2.3.4")).rejects.toMatchObject({
      code: "TURNSTILE_FAILED",
    });
    fetchMock.mockImplementation(() => Promise.resolve(Response.json({ success: true })));
    await expect(requireTurnstile(prodEnv, "tok", "1.2.3.4")).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      expect.anything(),
    );
  });

  it("is off in production when no site key is configured", async () => {
    await expect(
      requireTurnstile({ ...prodEnv, TURNSTILE_SITE_KEY: "" }, undefined, "1.2.3.4"),
    ).resolves.toBeUndefined();
  });

  it("refuses to run with a site key but no secret", async () => {
    await expect(
      requireTurnstile({ ...prodEnv, TURNSTILE_SECRET_KEY: "" }, "tok", "1.2.3.4"),
    ).rejects.toThrow();
  });
});
