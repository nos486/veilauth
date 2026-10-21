import type { Env } from "../env.js";
import { ApiError } from "./errors.js";

const VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

export function turnstileEnabled(env: Env): boolean {
  if (env.ENVIRONMENT !== "development") return true;
  return env.TURNSTILE_SITE_KEY !== "";
}

/** Verifies a Turnstile token. Disabled only in development without a site key. */
export async function requireTurnstile(
  env: Env,
  token: string | undefined,
  ip: string,
): Promise<void> {
  if (!turnstileEnabled(env)) return;
  const secret = env.TURNSTILE_SECRET_KEY;
  if (secret === undefined || secret === "")
    throw new Error("TURNSTILE_SECRET_KEY is not configured");
  if (token === undefined) throw new ApiError("TURNSTILE_REQUIRED");
  const form = new FormData();
  form.set("secret", secret);
  form.set("response", token);
  form.set("remoteip", ip);
  const res = await fetch(VERIFY_URL, { method: "POST", body: form });
  if (!res.ok) throw new ApiError("TURNSTILE_FAILED");
  const body: { success?: unknown } = await res.json();
  if (body.success !== true) throw new ApiError("TURNSTILE_FAILED");
}
