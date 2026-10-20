# Self-hosting on your own Cloudflare account

> Phase 0 status: the Worker does not exist yet. This page will be completed in Phase 1
> (Worker + D1) and Phase 2 (web assets).

Planned outline:

1. `pnpm install`
2. `wrangler d1 create veilauth-prod` and put the id in `apps/worker/wrangler.toml`
3. `wrangler secret put JWT_ED25519_PRIVATE_KEY`, `FAKE_SALT_SECRET`, `TURNSTILE_SECRET`
4. `wrangler d1 migrations apply veilauth-prod --remote`
5. `pnpm --filter @zk2fa/worker deploy`
