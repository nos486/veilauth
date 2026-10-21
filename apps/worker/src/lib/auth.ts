import { eq, sql } from "drizzle-orm";
import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../app-env.js";
import { devices, users } from "../db/schema.js";
import { ApiError } from "./errors.js";
import { verifyAccessToken } from "./jwt.js";

const LAST_SEEN_RESOLUTION_MS = 5 * 60 * 1000;

/** Verifies the bearer token, the device (not revoked) and the security stamp on every request. */
export const requireAuth: MiddlewareHandler<AppEnv> = async (c, next) => {
  const header = c.req.header("authorization");
  if (header?.startsWith("Bearer ") !== true) throw new ApiError("UNAUTHORIZED");
  const now = Date.now();
  const claims = await verifyAccessToken(c.env.JWT_PRIVATE_JWK, header.slice(7), now);
  const db = c.get("db");
  const row = await db
    .select({
      stamp: users.securityStamp,
      revokedAt: devices.revokedAt,
      lastSeenAt: devices.lastSeenAt,
    })
    .from(devices)
    .innerJoin(users, eq(users.id, devices.userId))
    .where(sql`${devices.id} = ${claims.did} AND ${users.id} = ${claims.sub}`)
    .get();
  if (row === undefined || row.revokedAt !== null || row.stamp !== claims.stamp) {
    throw new ApiError("SESSION_REVOKED");
  }
  if (now - row.lastSeenAt > LAST_SEEN_RESOLUTION_MS) {
    c.executionCtx.waitUntil(
      db.update(devices).set({ lastSeenAt: now }).where(eq(devices.id, claims.did)).run(),
    );
  }
  c.set("auth", { userId: claims.sub, deviceId: claims.did, stamp: claims.stamp });
  await next();
};
