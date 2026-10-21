import { verifyAuthHash } from "@zk2fa/crypto/server";
import { DeleteAccountRequest, type Device, type DevicesResponse, Id } from "@zk2fa/shared";
import { and, eq, isNull } from "drizzle-orm";
import { Hono } from "hono";
import type { AppEnv } from "../app-env.js";
import { auditLog, devices, refreshHistory, users, vaultItems } from "../db/schema.js";
import { auditInsert } from "../lib/audit.js";
import { requireAuth } from "../lib/auth.js";
import { rateLimit } from "../lib/counters.js";
import { fromBase64Url } from "../lib/encoding.js";
import { ApiError } from "../lib/errors.js";
import { body, parse } from "../lib/request.js";

export const deviceRoutes = new Hono<AppEnv>();
deviceRoutes.use(requireAuth);

deviceRoutes.get("/", async (c) => {
  const { userId, deviceId } = c.get("auth");
  const rows = await c
    .get("db")
    .select()
    .from(devices)
    .where(and(eq(devices.userId, userId), isNull(devices.revokedAt)))
    .orderBy(devices.createdAt)
    .all();
  const list: Device[] = rows.map((d) => ({
    id: d.id,
    platform: d.platform,
    nameEnc: d.nameEnc,
    createdAt: d.createdAt,
    lastSeenAt: d.lastSeenAt,
    current: d.id === deviceId,
  }));
  const res: DevicesResponse = { devices: list };
  return c.json(res);
});

deviceRoutes.delete("/:id", async (c) => {
  const id = parse(Id, c.req.param("id"));
  const db = c.get("db");
  const { userId } = c.get("auth");
  const now = Date.now();
  const [revoked] = await db.batch([
    db
      .update(devices)
      .set({ revokedAt: now })
      .where(and(eq(devices.id, id), eq(devices.userId, userId), isNull(devices.revokedAt)))
      .returning({ id: devices.id }),
    auditInsert(db, { userId, deviceId: id, event: "device_revoke", ipHash: c.get("ipHash"), now }),
  ]);
  if (revoked.length === 0) throw new ApiError("NOT_FOUND");
  return c.body(null, 204);
});

export const accountRoutes = new Hono<AppEnv>();
accountRoutes.use(requireAuth);

/** Hard delete. Requires a freshly derived authKey, not just a valid session. */
accountRoutes.delete("/", async (c) => {
  const req = await body(c, DeleteAccountRequest);
  const db = c.get("db");
  const { userId } = c.get("auth");
  await rateLimit(c.env, `delete:${userId}`);
  const user = await db.query.users.findFirst({ where: (u, { eq: e }) => e(u.id, userId) });
  if (user === undefined) throw new ApiError("SESSION_REVOKED");
  if (!(await verifyAuthHash(fromBase64Url(req.authKey), user.authSalt, user.authHash))) {
    throw new ApiError("INVALID_CREDENTIALS");
  }
  await db.batch([
    db.delete(vaultItems).where(eq(vaultItems.userId, userId)),
    db.delete(refreshHistory).where(eq(refreshHistory.userId, userId)),
    db.delete(devices).where(eq(devices.userId, userId)),
    db.delete(auditLog).where(eq(auditLog.userId, userId)),
    db.delete(users).where(eq(users.id, userId)),
  ]);
  return c.body(null, 204);
});
