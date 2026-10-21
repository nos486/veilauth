import { CURRENT_KDF_VERSION, DEFAULT_KDF_PARAMS } from "@zk2fa/crypto/server";
import { type ConfigResponse, LIMITS, type TimeResponse } from "@zk2fa/shared";
import { Hono } from "hono";
import type { AppEnv } from "../app-env.js";
import { turnstileEnabled } from "../lib/turnstile.js";

export const meta = new Hono<AppEnv>();

meta.get("/time", (c) => {
  const res: TimeResponse = { now: Date.now() };
  return c.json(res);
});

meta.get("/config", (c) => {
  const res: ConfigResponse = {
    turnstileSiteKey: turnstileEnabled(c.env) ? c.env.TURNSTILE_SITE_KEY : null,
    kdf: { alg: "argon2id", version: CURRENT_KDF_VERSION, params: { ...DEFAULT_KDF_PARAMS } },
    limits: {
      maxItemsPerUser: LIMITS.maxItemsPerUser,
      maxBlobChars: LIMITS.maxBlobChars,
      maxChangesPerPush: LIMITS.maxChangesPerPush,
    },
  };
  return c.json(res);
});
