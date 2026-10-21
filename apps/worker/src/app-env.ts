import type { DrizzleD1Database } from "drizzle-orm/d1";
import type { Env } from "./env.js";
import type * as schema from "./db/schema.js";

export interface AuthContext {
  userId: string;
  deviceId: string;
  stamp: string;
}

export interface AppEnv {
  Bindings: Env;
  Variables: {
    db: DrizzleD1Database<typeof schema>;
    ip: string;
    /** HMAC(IP_HASH_SECRET, ip), base64url — the only form in which an IP is stored */
    ipHash: string;
    auth: AuthContext;
  };
}
