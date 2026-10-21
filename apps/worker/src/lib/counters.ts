import { sql } from "drizzle-orm";
import type { DrizzleD1Database } from "drizzle-orm/d1";
import { counters } from "../db/schema.js";
import type * as schema from "../db/schema.js";
import type { Env } from "../env.js";
import { ApiError } from "./errors.js";

type Db = DrizzleD1Database<typeof schema>;

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** Per-minute limits through the Workers Rate Limiting binding (5 / 60 s per key). */
export async function rateLimit(env: Env, key: string): Promise<void> {
  const { success } = await env.RL_AUTH.limit({ key });
  if (!success) throw new ApiError("RATE_LIMITED", { retryAfterSeconds: 60 });
}

/** Increments a fixed-window counter and returns the new count. */
async function hit(db: Db, key: string, windowMs: number, now: number): Promise<number> {
  const rows = await db
    .insert(counters)
    .values({ key, count: 1, windowStart: now, lockedUntil: 0, expiresAt: now + windowMs })
    .onConflictDoUpdate({
      target: counters.key,
      set: {
        count: sql`CASE WHEN ${counters.windowStart} + ${windowMs} <= ${now} THEN 1 ELSE ${counters.count} + 1 END`,
        windowStart: sql`CASE WHEN ${counters.windowStart} + ${windowMs} <= ${now} THEN ${now} ELSE ${counters.windowStart} END`,
        expiresAt: sql`MAX(${counters.expiresAt}, ${now + windowMs})`,
      },
    })
    .returning({ count: counters.count });
  return rows[0]?.count ?? 1;
}

async function current(
  db: Db,
  key: string,
  windowMs: number,
  now: number,
): Promise<{ count: number; lockedUntil: number }> {
  const row = await db.query.counters.findFirst({ where: (c, { eq }) => eq(c.key, key) });
  if (row === undefined) return { count: 0, lockedUntil: 0 };
  const count = row.windowStart + windowMs <= now ? 0 : row.count;
  return { count, lockedUntil: row.lockedUntil };
}

/** Registration: 3 per hour per IP (build spec §5.4). */
export async function limitRegistration(db: Db, ipHash: string, now: number): Promise<void> {
  const count = await hit(db, `reg:${ipHash}`, HOUR, now);
  if (count > 3) throw new ApiError("RATE_LIMITED", { retryAfterSeconds: 3600 });
}

/**
 * Login / recovery failure policy (docs/DECISIONS.md D-024):
 *  - per (e-mail, IP): after 5 failures in 24 h, exponential lockout 1 min · 2^(n-5), capped at 1 h;
 *  - per e-mail (any IP): 3 failures in 1 h make Turnstile mandatory.
 * Keys use HMAC'd e-mail so unknown e-mails behave exactly like known ones.
 */
export const LOCK_THRESHOLD = 5;
export const TURNSTILE_THRESHOLD = 3;

export interface FailureState {
  lockedUntil: number;
  turnstileRequired: boolean;
}

export async function failureState(
  db: Db,
  emailKey: string,
  ipHash: string,
  now: number,
): Promise<FailureState> {
  const [pair, account] = await Promise.all([
    current(db, `lock:${emailKey}:${ipHash}`, DAY, now),
    current(db, `fail:${emailKey}`, HOUR, now),
  ]);
  return { lockedUntil: pair.lockedUntil, turnstileRequired: account.count >= TURNSTILE_THRESHOLD };
}

export async function recordFailure(
  db: Db,
  emailKey: string,
  ipHash: string,
  now: number,
): Promise<void> {
  const lockKey = `lock:${emailKey}:${ipHash}`;
  const [n] = await Promise.all([
    hit(db, lockKey, DAY, now),
    hit(db, `fail:${emailKey}`, HOUR, now),
  ]);
  if (n >= LOCK_THRESHOLD) {
    const lockMs = Math.min(MINUTE * 2 ** (n - LOCK_THRESHOLD), HOUR);
    await db
      .update(counters)
      .set({ lockedUntil: now + lockMs })
      .where(sql`${counters.key} = ${lockKey}`);
  }
}

export async function clearFailures(db: Db, emailKey: string, ipHash: string): Promise<void> {
  await db
    .delete(counters)
    .where(sql`${counters.key} IN (${`lock:${emailKey}:${ipHash}`}, ${`fail:${emailKey}`})`);
}
