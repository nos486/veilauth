import type {
  PreloginResponse,
  RecoverStartResponse,
  RefreshResponse,
  SessionResponse,
} from "@zk2fa/shared";
import { randomBytes, toBase64Url } from "@zk2fa/crypto";
import { describe, expect, it } from "vitest";
import { failureState } from "../src/lib/counters.js";
import { drizzle } from "drizzle-orm/d1";
import * as schema from "../src/db/schema.js";
import { call, env, expectError, freshIp, json, TestClient, uuidv7 } from "./helpers.js";

describe("prelogin", () => {
  it("returns a deterministic fake salt and default params for unknown e-mails", async () => {
    const ip = freshIp();
    const a = await json<PreloginResponse>(
      await call("/api/v1/auth/prelogin", { body: { email: "ghost@example.com" }, ip }),
    );
    const b = await json<PreloginResponse>(
      await call("/api/v1/auth/prelogin", { body: { email: " GHOST@example.com" }, ip }),
    );
    const c = await json<PreloginResponse>(
      await call("/api/v1/auth/prelogin", { body: { email: "other@example.com" }, ip }),
    );
    expect(a).toEqual(b);
    expect(a.kdf.salt).not.toBe(c.kdf.salt);
    expect(a.kdf).toMatchObject({ alg: "argon2id", version: 1, params: { m: 65536, t: 3, p: 1 } });
  });

  it("returns the stored params for a real account, in the same shape", async () => {
    const client = new TestClient();
    await client.register();
    const res = await json<PreloginResponse>(
      await call("/api/v1/auth/prelogin", { body: { email: client.email }, ip: client.ip }),
    );
    expect(res.kdf).toEqual(client.kdf);
  });
});

describe("register", () => {
  it("creates an account and returns a session", async () => {
    const client = new TestClient();
    const s = await client.register();
    expect(s.userId).toBe(client.userId);
    expect(s.deviceId).toBe(client.deviceId);
    expect(s.vaultRevision).toBe(0);
    expect(s.kdfUpgradeRequired).toBe(false);
    expect(s.refreshToken).toHaveLength(43);
  });

  it("rejects a duplicate e-mail regardless of case", async () => {
    const a = new TestClient();
    await a.register();
    const b = new TestClient(a.email.toUpperCase());
    await expectError(
      await call("/api/v1/auth/register", { body: await b.registerBody(), ip: b.ip }),
      409,
      "EMAIL_TAKEN",
    );
  });

  it.each([
    ["weak memory", { m: 1024, t: 3, p: 1 }],
    ["one pass", { m: 65536, t: 1, p: 1 }],
    ["four lanes", { m: 65536, t: 3, p: 4 }],
  ])("rejects downgraded KDF params (%s)", async (_n, params) => {
    const client = new TestClient();
    client.kdf = { ...client.kdf, params };
    await expectError(
      await call("/api/v1/auth/register", { body: await client.registerBody(), ip: client.ip }),
      400,
      "KDF_PARAMS_REJECTED",
    );
  });

  it("validates input without echoing it", async () => {
    const client = new TestClient();
    const body = { ...(await client.registerBody()), authKey: "SECRET-VALUE-THAT-MUST-NOT-ECHO" };
    const res = await call("/api/v1/auth/register", { body, ip: client.ip });
    const text = await res.text();
    expect(res.status).toBe(400);
    expect(text).toContain("authKey");
    expect(text).not.toContain("SECRET-VALUE");
  });

  it("limits registrations to 3 per hour per IP", async () => {
    const ip = freshIp();
    for (let i = 0; i < 3; i++) {
      const c = new TestClient();
      expect(
        (await call("/api/v1/auth/register", { body: await c.registerBody(), ip })).status,
      ).toBe(201);
    }
    const c = new TestClient();
    await expectError(
      await call("/api/v1/auth/register", { body: await c.registerBody(), ip }),
      429,
      "RATE_LIMITED",
    );
  });
});

describe("login", () => {
  it("returns the wrapped vault key and a working access token", async () => {
    const client = new TestClient();
    const reg = await client.register();
    const res = await client.login(uuidv7());
    expect(res.status).toBe(200);
    const s = await json<SessionResponse>(res);
    expect(s.wrappedVaultKey).toBe(reg.wrappedVaultKey);
    expect((await call("/api/v1/devices", { token: s.accessToken })).status).toBe(200);
  });

  it("gives the same error for a wrong key and an unknown e-mail", async () => {
    const client = new TestClient();
    await client.register();
    client.authKey = toBase64Url(randomBytes(32));
    await expectError(await client.login(), 401, "INVALID_CREDENTIALS");
    const ghost = new TestClient();
    await expectError(await ghost.login(), 401, "INVALID_CREDENTIALS");
  });

  it("locks (e-mail, IP) after 5 failures and escalates to Turnstile after 3", async () => {
    const client = new TestClient();
    await client.register();
    const good = client.authKey;
    client.authKey = toBase64Url(randomBytes(32));
    for (let i = 0; i < 5; i++) await expectError(await client.login(), 401, "INVALID_CREDENTIALS");
    const res = await client.login();
    expect(res.status).toBe(429);
    const db = drizzle(env.DB, { schema });
    const rows = await db.query.counters.findMany();
    const lock = rows.find((r) => r.key.startsWith("lock:") && r.lockedUntil > Date.now());
    expect(lock).toBeDefined();
    const emailKey = lock?.key.split(":")[1] ?? "";
    const ipHash = lock?.key.split(":")[2] ?? "";
    expect(await failureState(db, emailKey, ipHash, Date.now())).toMatchObject({
      turnstileRequired: true,
    });
    // Another IP is not locked out by someone else's failures.
    client.authKey = good;
    expect((await client.login(client.deviceId, freshIp())).status).toBe(200);
  });

  it("rejects a device id that belongs to another account", async () => {
    const a = new TestClient();
    await a.register();
    const b = new TestClient();
    await b.register();
    await expectError(await b.login(a.deviceId), 409, "ID_TAKEN");
  });
});

describe("refresh tokens", () => {
  it("rotates, and reuse of an old token revokes the whole family", async () => {
    const client = new TestClient();
    const s = await client.register();
    const r1 = await call("/api/v1/auth/refresh", { body: { refreshToken: s.refreshToken } });
    expect(r1.status).toBe(200);
    const t1 = await json<RefreshResponse>(r1);
    expect(t1.refreshToken).not.toBe(s.refreshToken);

    await expectError(
      await call("/api/v1/auth/refresh", { body: { refreshToken: s.refreshToken } }),
      401,
      "REFRESH_REUSED",
    );
    // The legitimate holder of the newest token is cut off as well.
    await expectError(
      await call("/api/v1/auth/refresh", { body: { refreshToken: t1.refreshToken } }),
      401,
      "SESSION_REVOKED",
    );
    await expectError(
      await call("/api/v1/devices", { token: t1.accessToken }),
      401,
      "SESSION_REVOKED",
    );
  });

  it("rejects unknown tokens", async () => {
    await expectError(
      await call("/api/v1/auth/refresh", { body: { refreshToken: toBase64Url(randomBytes(32)) } }),
      401,
      "UNAUTHORIZED",
    );
  });
});

describe("logout", () => {
  it("revokes the current session immediately", async () => {
    const client = new TestClient();
    await client.register();
    expect(
      (await call("/api/v1/auth/logout", { method: "POST", token: client.token })).status,
    ).toBe(204);
    await expectError(
      await call("/api/v1/devices", { token: client.token }),
      401,
      "SESSION_REVOKED",
    );
  });
});

describe("change password", () => {
  it("swaps the auth hash and wrap atomically and logs out every other device", async () => {
    const client = new TestClient();
    await client.register();
    const other = await json<SessionResponse>(await client.login(uuidv7()));

    const newAuthKey = toBase64Url(randomBytes(32));
    const newKdf = { ...client.kdf, salt: toBase64Url(randomBytes(16)) };
    const newWrap = toBase64Url(Uint8Array.from({ length: 61 }, (_, i) => (i === 0 ? 1 : i)));
    const res = await call("/api/v1/auth/change-password", {
      token: client.token,
      body: { authKey: client.authKey, newKdf, newAuthKey, newWrappedVaultKey: newWrap },
    });
    expect(res.status).toBe(200);
    const s = await json<SessionResponse>(res);
    expect(s.wrappedVaultKey).toBe(newWrap);

    // Old access token (old stamp) and the other device are dead; the new token works.
    await expectError(
      await call("/api/v1/devices", { token: client.token }),
      401,
      "SESSION_REVOKED",
    );
    await expectError(
      await call("/api/v1/devices", { token: other.accessToken }),
      401,
      "SESSION_REVOKED",
    );
    await expectError(
      await call("/api/v1/auth/refresh", { body: { refreshToken: other.refreshToken } }),
      401,
      "SESSION_REVOKED",
    );
    expect((await call("/api/v1/devices", { token: s.accessToken })).status).toBe(200);

    await expectError(await client.login(), 401, "INVALID_CREDENTIALS");
    client.authKey = newAuthKey;
    const relog = await json<SessionResponse>(await client.login(uuidv7()));
    expect(relog.kdf).toEqual(newKdf);
  });

  it("requires the current authKey", async () => {
    const client = new TestClient();
    await client.register();
    await expectError(
      await call("/api/v1/auth/change-password", {
        token: client.token,
        body: {
          authKey: toBase64Url(randomBytes(32)),
          newKdf: client.kdf,
          newAuthKey: toBase64Url(randomBytes(32)),
          newWrappedVaultKey: toBase64Url(randomBytes(61)),
        },
      }),
      401,
      "INVALID_CREDENTIALS",
    );
  });
});

describe("recovery", () => {
  it("verifies the recovery key, replaces credentials and revokes all sessions", async () => {
    const client = new TestClient();
    const reg = await client.register();
    await expectError(
      await call("/api/v1/auth/recover/start", {
        body: { email: client.email, recoveryAuthKey: toBase64Url(randomBytes(32)) },
        ip: client.ip,
      }),
      401,
      "INVALID_CREDENTIALS",
    );
    const start = await json<RecoverStartResponse>(
      await call("/api/v1/auth/recover/start", {
        body: { email: client.email, recoveryAuthKey: client.recoveryAuth },
        ip: client.ip,
      }),
    );
    expect(start.userId).toBe(client.userId);

    const newRecoveryAuth = toBase64Url(randomBytes(32));
    const newAuthKey = toBase64Url(randomBytes(32));
    const res = await call("/api/v1/auth/recover", {
      ip: client.ip,
      body: {
        email: client.email,
        recoveryAuthKey: client.recoveryAuth,
        newKdf: { ...client.kdf, salt: toBase64Url(randomBytes(16)) },
        newAuthKey,
        newWrappedVaultKey: toBase64Url(randomBytes(61)),
        newRecovery: { authKey: newRecoveryAuth, wrappedVaultKey: toBase64Url(randomBytes(61)) },
        device: { id: uuidv7(), platform: "web", nameEnc: null },
      },
    });
    expect(res.status).toBe(200);
    await expectError(
      await call("/api/v1/devices", { token: reg.accessToken }),
      401,
      "SESSION_REVOKED",
    );
    // The old recovery key is single-use.
    await expectError(
      await call("/api/v1/auth/recover/start", {
        body: { email: client.email, recoveryAuthKey: client.recoveryAuth },
        ip: client.ip,
      }),
      401,
      "INVALID_CREDENTIALS",
    );
    client.authKey = newAuthKey;
    expect((await client.login(uuidv7())).status).toBe(200);
  });
});
