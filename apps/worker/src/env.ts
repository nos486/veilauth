export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  /** Workers Rate Limiting binding: 5 requests / 60 s per key (login, prelogin, recovery) */
  RL_AUTH: RateLimit;
  /** Public Turnstile site key; empty disables Turnstile (D-049) */
  TURNSTILE_SITE_KEY: string;
  // Secrets (wrangler secret put / .dev.vars)
  TURNSTILE_SECRET_KEY?: string;
  /** Ed25519 private key as JWK JSON */
  JWT_PRIVATE_JWK: string;
  /** ≥ 32 random bytes, base64url */
  FAKE_SALT_SECRET: string;
  /** ≥ 32 random bytes, base64url; keys IP hashes in the audit log and counters */
  IP_HASH_SECRET: string;
}
