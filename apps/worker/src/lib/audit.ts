import type { DrizzleD1Database } from "drizzle-orm/d1";
import { auditLog } from "../db/schema.js";
import type * as schema from "../db/schema.js";
import { uuidv7 } from "./encoding.js";

export type AuditEvent =
  | "register"
  | "login"
  | "login_failed"
  | "refresh_reuse"
  | "logout"
  | "password_change"
  | "recovery_start_failed"
  | "recover"
  | "device_revoke"
  | "account_delete";

export function auditInsert(
  db: DrizzleD1Database<typeof schema>,
  e: { userId: string; deviceId: string | null; event: AuditEvent; ipHash: string; now: number },
) {
  return db.insert(auditLog).values({
    id: uuidv7(e.now),
    userId: e.userId,
    deviceId: e.deviceId,
    event: e.event,
    ipHash: e.ipHash,
    createdAt: e.now,
  });
}
