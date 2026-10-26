import { drizzle } from "drizzle-orm/d1";
import { Hono } from "hono";
import { routePath } from "hono/route";
import type { AppEnv } from "./app-env.js";
import { runMaintenance } from "./cron.js";
import * as schema from "./db/schema.js";
import type { Env } from "./env.js";
import { ApiError } from "./lib/errors.js";
import { securityHeaders } from "./lib/headers.js";
import { pseudonym } from "./lib/hmac.js";
import { logError } from "./lib/log.js";
import { accountRoutes, deviceRoutes } from "./routes/account.js";
import { auth } from "./routes/auth.js";
import { meta } from "./routes/meta.js";
import { sync } from "./routes/sync.js";

const api = new Hono<AppEnv>();

const REQUIRED_SECRETS = ["JWT_PRIVATE_JWK", "FAKE_SALT_SECRET", "IP_HASH_SECRET"] as const;

api.use(async (c, next) => {
  const missing = REQUIRED_SECRETS.filter((name) => !c.env[name]);
  if (missing.length > 0) {
    // Names only: tells the operator which secret to add in the dashboard (docs/SELF_HOSTING.md).
    logError("missing_secrets", { missing, path: c.req.path });
    throw new ApiError("INTERNAL");
  }
  const ip = c.req.header("cf-connecting-ip") ?? "0.0.0.0";
  c.set("ip", ip);
  c.set("ipHash", await pseudonym(c.env.IP_HASH_SECRET, `ip:${ip}`));
  c.set("db", drizzle(c.env.DB, { schema }));
  await next();
});

api.route("/", meta);
api.route("/auth", auth);
api.route("/sync", sync);
api.route("/devices", deviceRoutes);
api.route("/account", accountRoutes);

api.notFound((c) => c.json({ code: "NOT_FOUND", message: "Not found." }, 404));

const onError: Parameters<typeof api.onError>[0] = (err, c) => {
  if (err instanceof ApiError) {
    if (err.retryAfterSeconds !== undefined) c.header("Retry-After", String(err.retryAfterSeconds));
    return c.json({ code: err.code, message: err.message }, err.status);
  }
  // Log only the error class and route; messages may contain SQL or request fragments.
  const schemaMissing = /no such table/.test(`${err.message} ${String(err.cause)}`);
  logError("unhandled", {
    name: err.name,
    path: routePath(c, -1),
    ...(schemaMissing ? { hint: "D1_SCHEMA_MISSING" as const } : {}),
  });
  return c.json({ code: "INTERNAL", message: "Internal error." }, 500);
};
api.onError(onError);

const app = new Hono<AppEnv>();
app.use("/api/*", securityHeaders);
app.onError(onError);
app.route("/api/v1", api);
// Any other /api path is an API 404, never the SPA fallback.
app.all("/api/*", (c) => c.json({ code: "NOT_FOUND", message: "Not found." }, 404));
app.all("*", (c) => c.env.ASSETS.fetch(c.req.raw));

export default {
  fetch: app.fetch,
  scheduled(_controller, env, ctx) {
    ctx.waitUntil(runMaintenance(drizzle(env.DB, { schema }), Date.now()));
  },
} satisfies ExportedHandler<Env>;

export { app };
