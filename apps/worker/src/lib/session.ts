import { CURRENT_KDF_VERSION } from "@zk2fa/crypto/server";
import { LIMITS, type DeviceInfo, type SessionResponse } from "@zk2fa/shared";
import { sql } from "drizzle-orm";
import type { DrizzleD1Database } from "drizzle-orm/d1";
import { devices, type UserRow } from "../db/schema.js";
import type * as schema from "../db/schema.js";
import type { Env } from "../env.js";
import { randomBytes, sha256, toBase64Url, uuidv7 } from "./encoding.js";
import { ApiError } from "./errors.js";
import { signAccessToken } from "./jwt.js";
import { kdfOf } from "./kdf.js";

type Db = DrizzleD1Database<typeof schema>;

export interface RefreshToken {
  token: string;
  hash: Uint8Array<ArrayBuffer>;
}

export async function newRefreshToken(): Promise<RefreshToken> {
  const raw = randomBytes(32);
  return { token: toBase64Url(raw), hash: await sha256(raw) };
}

export async function issueAccessToken(
  env: Env,
  s: { userId: string; deviceId: string; stamp: string },
  now: number,
): Promise<{ accessToken: string; accessTokenExpiresAt: number }> {
  const exp = now + LIMITS.accessTokenTtlMs;
  const accessToken = await signAccessToken(env.JWT_PRIVATE_JWK, {
    iss: "veilauth",
    sub: s.userId,
    did: s.deviceId,
    stamp: s.stamp,
    iat: Math.floor(now / 1000),
    exp: Math.floor(exp / 1000),
  });
  return { accessToken, accessTokenExpiresAt: exp };
}

/** Rejects a client-chosen device id that already belongs to another account. */
export async function assertDeviceIdAvailable(
  db: Db,
  deviceId: string,
  userId: string | null,
): Promise<void> {
  const existing = await db.query.devices.findFirst({ where: (d, { eq }) => eq(d.id, deviceId) });
  if (existing !== undefined && existing.userId !== userId) throw new ApiError("ID_TAKEN");
}

/** Insert or re-activate the device row for a fresh login (new refresh family). */
export function upsertDevice(
  db: Db,
  userId: string,
  device: DeviceInfo,
  refresh: RefreshToken,
  now: number,
) {
  const values = {
    id: device.id,
    userId,
    nameEnc: device.nameEnc,
    platform: device.platform,
    refreshHash: refresh.hash,
    refreshFamily: uuidv7(now),
    refreshExpiresAt: now + LIMITS.refreshTokenTtlMs,
    lastSeenAt: now,
    createdAt: now,
    revokedAt: null,
  };
  return db
    .insert(devices)
    .values(values)
    .onConflictDoUpdate({
      target: devices.id,
      set: {
        nameEnc: values.nameEnc,
        platform: values.platform,
        refreshHash: values.refreshHash,
        refreshFamily: values.refreshFamily,
        refreshExpiresAt: values.refreshExpiresAt,
        lastSeenAt: now,
        revokedAt: null,
      },
      setWhere: sql`${devices.userId} = ${userId}`,
    });
}

export async function sessionResponse(
  env: Env,
  user: Pick<
    UserRow,
    | "id"
    | "securityStamp"
    | "wrappedVaultKey"
    | "kdfAlg"
    | "kdfVersion"
    | "kdfParams"
    | "kdfSalt"
    | "vaultRevision"
  >,
  deviceId: string,
  refresh: RefreshToken,
  now: number,
): Promise<SessionResponse> {
  const access = await issueAccessToken(
    env,
    { userId: user.id, deviceId, stamp: user.securityStamp },
    now,
  );
  return {
    userId: user.id,
    deviceId,
    ...access,
    refreshToken: refresh.token,
    wrappedVaultKey: user.wrappedVaultKey,
    kdf: kdfOf(user),
    vaultRevision: user.vaultRevision,
    kdfUpgradeRequired: user.kdfVersion < CURRENT_KDF_VERSION,
  };
}
