import {
  computeAuthHash,
  CURRENT_KDF_VERSION,
  DEFAULT_KDF_PARAMS,
  fakeSalt,
  generateAuthSalt,
  normalizeEmail,
  verifyAuthHash,
} from "@zk2fa/crypto/server";
import {
  ChangePasswordRequest,
  LoginRequest,
  PreloginRequest,
  type PreloginResponse,
  RecoverRequest,
  RecoverStartRequest,
  type RecoverStartResponse,
  RefreshRequest,
  type RefreshResponse,
  RegisterRequest,
} from "@zk2fa/shared";
import { and, eq, isNull, ne, sql } from "drizzle-orm";
import { type Context, Hono } from "hono";
import type { AppEnv } from "../app-env.js";
import { devices, refreshHistory, users, type UserRow } from "../db/schema.js";
import { auditInsert } from "../lib/audit.js";
import { requireAuth } from "../lib/auth.js";
import {
  clearFailures,
  failureState,
  limitRegistration,
  rateLimit,
  recordFailure,
} from "../lib/counters.js";
import { fromBase64Url, randomBytes, sha256, toBase64Url, uuidv7 } from "../lib/encoding.js";
import { ApiError } from "../lib/errors.js";
import { pseudonym } from "../lib/hmac.js";
import { acceptKdf } from "../lib/kdf.js";
import { body } from "../lib/request.js";
import {
  assertDeviceIdAvailable,
  issueAccessToken,
  newRefreshToken,
  sessionResponse,
  upsertDevice,
} from "../lib/session.js";
import { requireTurnstile } from "../lib/turnstile.js";

export const auth = new Hono<AppEnv>();

async function emailKey(secret: string, email: string): Promise<string> {
  return pseudonym(secret, `email:${email}`);
}

async function findUser(c: Context<AppEnv>, email: string): Promise<UserRow | undefined> {
  return c.get("db").query.users.findFirst({ where: (u, { eq: e }) => e(u.email, email) });
}

/** Burns the same PBKDF2 cost for unknown accounts so timing does not reveal existence. */
async function dummyVerify(secret: Uint8Array): Promise<void> {
  await computeAuthHash(secret, randomBytes(16));
}

/**
 * Shared guard for password and recovery-key checks: per-minute rate limit, lockout,
 * Turnstile escalation, constant-time verification, failure accounting.
 */
async function verifySecret(
  c: Context<AppEnv>,
  opts: {
    purpose: "login" | "recover";
    email: string;
    secretB64: string;
    turnstileToken: string | undefined;
    pick: (u: UserRow) => { hash: Uint8Array; salt: Uint8Array };
  },
): Promise<UserRow> {
  const db = c.get("db");
  const ipHash = c.get("ipHash");
  const now = Date.now();
  const ek = await emailKey(c.env.IP_HASH_SECRET, opts.email);
  await rateLimit(c.env, `${opts.purpose}:${ipHash}:${ek}`);
  const state = await failureState(db, ek, ipHash, now);
  if (state.lockedUntil > now) {
    throw new ApiError("ACCOUNT_LOCKED", {
      retryAfterSeconds: Math.ceil((state.lockedUntil - now) / 1000),
    });
  }
  if (state.turnstileRequired) await requireTurnstile(c.env, opts.turnstileToken, c.get("ip"));

  const secret = fromBase64Url(opts.secretB64);
  const user = await findUser(c, opts.email);
  let ok = false;
  if (user === undefined) {
    await dummyVerify(secret);
  } else {
    const { hash, salt } = opts.pick(user);
    ok = await verifyAuthHash(secret, salt, hash);
  }
  secret.fill(0);
  if (!ok || user === undefined) {
    await recordFailure(db, ek, ipHash, now);
    if (user !== undefined) {
      const event = opts.purpose === "login" ? "login_failed" : "recovery_start_failed";
      await auditInsert(db, { userId: user.id, deviceId: null, event, ipHash, now });
    }
    throw new ApiError("INVALID_CREDENTIALS");
  }
  await clearFailures(db, ek, ipHash);
  return user;
}

auth.post("/prelogin", async (c) => {
  const req = await body(c, PreloginRequest);
  const email = normalizeEmail(req.email);
  const ek = await emailKey(c.env.IP_HASH_SECRET, email);
  await rateLimit(c.env, `prelogin:${c.get("ipHash")}:${ek}`);
  // Always compute the fake salt so both paths do the same work.
  const fake = await fakeSalt(fromBase64Url(c.env.FAKE_SALT_SECRET), email);
  const user = await findUser(c, email);
  const res: PreloginResponse = {
    kdf:
      user === undefined
        ? {
            alg: "argon2id",
            version: CURRENT_KDF_VERSION,
            params: { ...DEFAULT_KDF_PARAMS },
            salt: toBase64Url(fake),
          }
        : {
            alg: "argon2id",
            version: user.kdfVersion,
            params: JSON.parse(user.kdfParams) as { m: number; t: number; p: number },
            salt: toBase64Url(user.kdfSalt),
          },
  };
  return c.json(res);
});

auth.post("/register", async (c) => {
  const req = await body(c, RegisterRequest);
  const db = c.get("db");
  const now = Date.now();
  const ipHash = c.get("ipHash");
  await limitRegistration(db, ipHash, now);
  await requireTurnstile(c.env, req.turnstileToken, c.get("ip"));
  const kdf = acceptKdf(req.kdf);
  const email = normalizeEmail(req.email);
  if ((await findUser(c, email)) !== undefined) throw new ApiError("EMAIL_TAKEN");
  if (
    (await db.query.users.findFirst({ where: (u, { eq: e }) => e(u.id, req.userId) })) !== undefined
  ) {
    throw new ApiError("ID_TAKEN");
  }
  await assertDeviceIdAvailable(db, req.device.id, null);

  const authSalt = generateAuthSalt();
  const recoverySalt = generateAuthSalt();
  const [authHash, recoveryHash] = await Promise.all([
    computeAuthHash(fromBase64Url(req.authKey), authSalt),
    computeAuthHash(fromBase64Url(req.recovery.authKey), recoverySalt),
  ]);
  const user: UserRow = {
    id: req.userId,
    email,
    emailVerified: false,
    kdfAlg: kdf.alg,
    kdfParams: kdf.params,
    kdfSalt: kdf.salt,
    kdfVersion: kdf.version,
    authHash,
    authSalt,
    wrappedVaultKey: req.wrappedVaultKey,
    recoveryWrappedVaultKey: req.recovery.wrappedVaultKey,
    recoveryAuthHash: recoveryHash,
    recoveryAuthSalt: recoverySalt,
    vaultRevision: 0,
    tombstoneHorizon: 0,
    securityStamp: uuidv7(now),
    createdAt: now,
    updatedAt: now,
  };
  const refresh = await newRefreshToken();
  try {
    await db.batch([
      db.insert(users).values(user),
      upsertDevice(db, user.id, req.device, refresh, now),
      auditInsert(db, { userId: user.id, deviceId: req.device.id, event: "register", ipHash, now }),
    ]);
  } catch (e: unknown) {
    // Lost a race against a concurrent registration with the same e-mail.
    if (
      e instanceof Error &&
      /UNIQUE constraint failed: users\.email/.test(e.message + String(e.cause))
    ) {
      throw new ApiError("EMAIL_TAKEN");
    }
    throw e;
  }
  return c.json(await sessionResponse(c.env, user, req.device.id, refresh, now), 201);
});

auth.post("/login", async (c) => {
  const req = await body(c, LoginRequest);
  const db = c.get("db");
  const email = normalizeEmail(req.email);
  const user = await verifySecret(c, {
    purpose: "login",
    email,
    secretB64: req.authKey,
    turnstileToken: req.turnstileToken,
    pick: (u) => ({ hash: u.authHash, salt: u.authSalt }),
  });
  const now = Date.now();
  await assertDeviceIdAvailable(db, req.device.id, user.id);
  const refresh = await newRefreshToken();
  await db.batch([
    upsertDevice(db, user.id, req.device, refresh, now),
    auditInsert(db, {
      userId: user.id,
      deviceId: req.device.id,
      event: "login",
      ipHash: c.get("ipHash"),
      now,
    }),
  ]);
  return c.json(await sessionResponse(c.env, user, req.device.id, refresh, now));
});

auth.post("/refresh", async (c) => {
  const req = await body(c, RefreshRequest);
  const db = c.get("db");
  const now = Date.now();
  const hash = await sha256(fromBase64Url(req.refreshToken));
  const device = await db.query.devices.findFirst({
    where: (d, { eq: e }) => e(d.refreshHash, hash),
  });

  if (device === undefined) {
    // A rotated token presented again: someone kept a copy. Revoke the whole family (build spec §5.4).
    const reused = await db.query.refreshHistory.findFirst({
      where: (r, { eq: e }) => e(r.tokenHash, hash),
    });
    if (reused !== undefined) {
      const victim = await db.query.devices.findFirst({
        where: (d, { eq: e }) => e(d.refreshFamily, reused.family),
      });
      await db.batch([
        db.update(devices).set({ revokedAt: now }).where(eq(devices.refreshFamily, reused.family)),
        auditInsert(db, {
          userId: reused.userId,
          deviceId: victim?.id ?? null,
          event: "refresh_reuse",
          ipHash: c.get("ipHash"),
          now,
        }),
      ]);
      throw new ApiError("REFRESH_REUSED");
    }
    throw new ApiError("UNAUTHORIZED");
  }
  if (device.revokedAt !== null || device.refreshExpiresAt <= now)
    throw new ApiError("SESSION_REVOKED");
  const user = await db.query.users.findFirst({ where: (u, { eq: e }) => e(u.id, device.userId) });
  if (user === undefined) throw new ApiError("SESSION_REVOKED");

  const next = await newRefreshToken();
  // Conditional on the old hash so two concurrent refreshes cannot both succeed.
  const [updated] = await db.batch([
    db
      .update(devices)
      .set({ refreshHash: next.hash, lastSeenAt: now })
      .where(
        and(eq(devices.id, device.id), eq(devices.refreshHash, hash), isNull(devices.revokedAt)),
      )
      .returning({ id: devices.id }),
    db
      .insert(refreshHistory)
      .values({
        tokenHash: hash,
        family: device.refreshFamily,
        userId: device.userId,
        expiresAt: device.refreshExpiresAt,
      })
      .onConflictDoNothing(),
  ]);
  if (updated.length !== 1) throw new ApiError("UNAUTHORIZED");
  const access = await issueAccessToken(
    c.env,
    { userId: user.id, deviceId: device.id, stamp: user.securityStamp },
    now,
  );
  const res: RefreshResponse = { ...access, refreshToken: next.token };
  return c.json(res);
});

auth.post("/logout", requireAuth, async (c) => {
  const db = c.get("db");
  const { userId, deviceId } = c.get("auth");
  const now = Date.now();
  await db.batch([
    db
      .update(devices)
      .set({ revokedAt: now })
      .where(and(eq(devices.id, deviceId), eq(devices.userId, userId))),
    auditInsert(db, { userId, deviceId, event: "logout", ipHash: c.get("ipHash"), now }),
  ]);
  return c.body(null, 204);
});

auth.post("/change-password", requireAuth, async (c) => {
  const req = await body(c, ChangePasswordRequest);
  const db = c.get("db");
  const { userId, deviceId } = c.get("auth");
  const user = await db.query.users.findFirst({ where: (u, { eq: e }) => e(u.id, userId) });
  if (user === undefined) throw new ApiError("SESSION_REVOKED");
  const user2 = await verifySecret(c, {
    purpose: "login",
    email: user.email,
    secretB64: req.authKey,
    turnstileToken: undefined,
    pick: (u) => ({ hash: u.authHash, salt: u.authSalt }),
  });
  if (user2.id !== userId) throw new ApiError("FORBIDDEN");
  const kdf = acceptKdf(req.newKdf);
  const now = Date.now();
  const authSalt = generateAuthSalt();
  const authHash = await computeAuthHash(fromBase64Url(req.newAuthKey), authSalt);
  const stamp = uuidv7(now);
  const refresh = await newRefreshToken();
  const current = await db.query.devices.findFirst({ where: (d, { eq: e }) => e(d.id, deviceId) });
  if (current === undefined) throw new ApiError("SESSION_REVOKED");
  await db.batch([
    db
      .update(users)
      .set({
        kdfAlg: kdf.alg,
        kdfParams: kdf.params,
        kdfSalt: kdf.salt,
        kdfVersion: kdf.version,
        authHash,
        authSalt,
        wrappedVaultKey: req.newWrappedVaultKey,
        securityStamp: stamp,
        updatedAt: now,
      })
      .where(eq(users.id, userId)),
    db
      .update(devices)
      .set({ revokedAt: now })
      .where(and(eq(devices.userId, userId), ne(devices.id, deviceId))),
    upsertDevice(
      db,
      userId,
      { id: deviceId, platform: current.platform, nameEnc: current.nameEnc },
      refresh,
      now,
    ),
    auditInsert(db, { userId, deviceId, event: "password_change", ipHash: c.get("ipHash"), now }),
  ]);
  const updated = {
    ...user,
    kdfAlg: kdf.alg,
    kdfParams: kdf.params,
    kdfSalt: kdf.salt,
    kdfVersion: kdf.version,
  };
  return c.json(
    await sessionResponse(
      c.env,
      { ...updated, securityStamp: stamp, wrappedVaultKey: req.newWrappedVaultKey },
      deviceId,
      refresh,
      now,
    ),
  );
});

auth.post("/recover/start", async (c) => {
  const req = await body(c, RecoverStartRequest);
  const user = await verifySecret(c, {
    purpose: "recover",
    email: normalizeEmail(req.email),
    secretB64: req.recoveryAuthKey,
    turnstileToken: undefined,
    pick: (u) => ({ hash: u.recoveryAuthHash, salt: u.recoveryAuthSalt }),
  });
  const res: RecoverStartResponse = {
    userId: user.id,
    recoveryWrappedVaultKey: user.recoveryWrappedVaultKey,
  };
  return c.json(res);
});

auth.post("/recover", async (c) => {
  const req = await body(c, RecoverRequest);
  const db = c.get("db");
  const user = await verifySecret(c, {
    purpose: "recover",
    email: normalizeEmail(req.email),
    secretB64: req.recoveryAuthKey,
    turnstileToken: undefined,
    pick: (u) => ({ hash: u.recoveryAuthHash, salt: u.recoveryAuthSalt }),
  });
  const kdf = acceptKdf(req.newKdf);
  await assertDeviceIdAvailable(db, req.device.id, user.id);
  const now = Date.now();
  const authSalt = generateAuthSalt();
  const recoverySalt = generateAuthSalt();
  const [authHash, recoveryHash] = await Promise.all([
    computeAuthHash(fromBase64Url(req.newAuthKey), authSalt),
    computeAuthHash(fromBase64Url(req.newRecovery.authKey), recoverySalt),
  ]);
  const stamp = uuidv7(now);
  const refresh = await newRefreshToken();
  const patch = {
    kdfAlg: kdf.alg,
    kdfParams: kdf.params,
    kdfSalt: kdf.salt,
    kdfVersion: kdf.version,
    authHash,
    authSalt,
    wrappedVaultKey: req.newWrappedVaultKey,
    recoveryWrappedVaultKey: req.newRecovery.wrappedVaultKey,
    recoveryAuthHash: recoveryHash,
    recoveryAuthSalt: recoverySalt,
    securityStamp: stamp,
    updatedAt: now,
  };
  await db.batch([
    db.update(users).set(patch).where(eq(users.id, user.id)),
    db
      .update(devices)
      .set({ revokedAt: now })
      .where(and(eq(devices.userId, user.id), sql`${devices.revokedAt} IS NULL`)),
    upsertDevice(db, user.id, req.device, refresh, now),
    auditInsert(db, {
      userId: user.id,
      deviceId: req.device.id,
      event: "recover",
      ipHash: c.get("ipHash"),
      now,
    }),
  ]);
  return c.json(await sessionResponse(c.env, { ...user, ...patch }, req.device.id, refresh, now));
});
