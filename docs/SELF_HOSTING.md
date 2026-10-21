# Deploying veilauth to Cloudflare

veilauth runs entirely on Cloudflare: one **Worker** serves the API (`/api/v1/*`) and the web
app's static files from the same origin, **D1** stores the encrypted vault, and the **Rate
Limiting** binding plus **Turnstile** protect the login endpoints. Everything fits in the Workers
Free plan for personal use. The Workers Paid plan ($5/month) gives you more D1 and CPU headroom.

You need:

- a Cloudflare account (free) and, optionally, a domain on Cloudflare;
- Node 22 and pnpm 10 (`corepack enable`);
- this repository cloned locally.

All commands below run from `apps/worker/` unless they say otherwise.

```sh
pnpm install            # at the repo root
pnpm build              # at the repo root: builds @zk2fa/crypto and @zk2fa/shared
cd apps/worker
```

## 1. Log in to Cloudflare

```sh
npx wrangler login      # opens a browser; or set CLOUDFLARE_API_TOKEN for CI
npx wrangler whoami     # note your Account ID
```

## 2. Create the D1 databases

```sh
node scripts/setup-cloudflare.mjs staging production
```

The script creates `veilauth-staging` and `veilauth-production` (if they don't exist yet) and
writes their ids into `wrangler.jsonc` in place of `REPLACE_WITH_*_D1_ID`. Commit that change:
database ids are not secret.

To do it by hand instead, run `npx wrangler d1 create veilauth-production` and paste the
`database_id` it prints into `env.production.d1_databases[0].database_id`.

## 3. Create a Turnstile widget (production)

1. Dashboard → **Turnstile** → **Add widget**.
2. Hostname: the domain you will serve veilauth on (for example `vault.example.com`, or
   `veilauth.<your-subdomain>.workers.dev`).
3. Widget mode: **Managed**.
4. Copy the **site key** into `wrangler.jsonc` → `env.production.vars.TURNSTILE_SITE_KEY`
   (it is public). Keep the **secret key** for step 4.

Staging uses Cloudflare's always-pass test keys, so automated tests can register accounts.

## 4. Set the secrets

```sh
node scripts/generate-secrets.mjs --env staging
node scripts/generate-secrets.mjs --env production
npx wrangler secret put TURNSTILE_SECRET_KEY --env production   # paste the Turnstile secret key
```

| Secret                 | What it is                                                                           |
| ---------------------- | ------------------------------------------------------------------------------------ |
| `JWT_PRIVATE_JWK`      | Ed25519 private key that signs 15-minute access tokens                               |
| `FAKE_SALT_SECRET`     | HMAC key for fake prelogin salts (prevents account enumeration)                      |
| `IP_HASH_SECRET`       | HMAC key that pseudonymises IPs and e-mails in the audit log and rate-limit counters |
| `TURNSTILE_SECRET_KEY` | Turnstile server-side secret                                                         |

Generate these **once per environment**. Rotating `JWT_PRIVATE_JWK` logs every device out.
Rotating `FAKE_SALT_SECRET` changes the fake salts, which lets an observer tell real accounts
from fake ones. The script never prints the values. They exist only in Cloudflare.

## 5. Apply the database migrations

```sh
pnpm db:migrate:staging
pnpm db:migrate:production
```

## 6. Deploy

```sh
pnpm deploy:staging
pnpm deploy:production
```

Wrangler prints the URL, for example `https://veilauth.<subdomain>.workers.dev`. Check it:

```sh
curl https://veilauth.<subdomain>.workers.dev/api/v1/time
# {"now":1792562498116}
```

### Custom domain (recommended)

Dashboard → **Workers & Pages** → `veilauth` → **Settings** → **Domains & Routes** → **Add** →
**Custom domain** → `vault.example.com`. Cloudflare issues the certificate. Then turn off the
`workers.dev` route on the same page so the app has a single origin.

## 7. Continuous deployment from GitHub (optional, recommended)

The repository ships three workflows:

| Workflow             | Trigger           | What it does                                                                                                     |
| -------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------- |
| `ci.yml`             | every PR and push | lint, typecheck, tests (including Worker tests on a local D1), vector + OpenAPI drift checks, audit, secret scan |
| `deploy-staging.yml` | push to `main`    | D1 migrations → `wrangler deploy --env staging` → smoke test                                                     |
| `release.yml`        | tag `v*`          | production migrations + deploy → smoke test → GitHub Release with build artifacts and `SHA256SUMS`               |

Set these in GitHub → **Settings** → **Secrets and variables** → **Actions**:

| Name                    | Kind     | Value                                                                                                                                         |
| ----------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `CLOUDFLARE_API_TOKEN`  | secret   | Dashboard → My Profile → API Tokens → **Create token** → template **Edit Cloudflare Workers**, and add the permission **Account · D1 · Edit** |
| `CLOUDFLARE_ACCOUNT_ID` | secret   | from `wrangler whoami`                                                                                                                        |
| `STAGING_URL`           | variable | e.g. `https://veilauth-staging.<subdomain>.workers.dev`                                                                                       |
| `PRODUCTION_URL`        | variable | e.g. `https://vault.example.com`                                                                                                              |

Then create a GitHub **environment** called `production` (Settings → Environments) and add
yourself as a required reviewer, so every production deploy waits for your approval.

Releasing:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

Until `CLOUDFLARE_API_TOKEN` is set, the deploy jobs skip themselves with a notice instead of
failing.

## Local development

```sh
cd apps/worker
node scripts/generate-secrets.mjs --dev   # writes .dev.vars (git-ignored)
pnpm db:migrate:local
pnpm dev                                  # http://localhost:8787
```

Turnstile is off in local development (`ENVIRONMENT=development` with an empty site key). It is
always on in staging and production. The Worker refuses Turnstile-protected requests if the
secret is missing.

## Operations

- **Logs:** Dashboard → Workers → veilauth → **Logs** (Workers Logs is enabled). Only error
  class names and route paths are logged, never request data.
- **Backups:** D1 Time Travel restores the database to any minute in the last 30 days
  (`npx wrangler d1 time-travel restore veilauth-production --timestamp=...`). The data is
  ciphertext, so a backup is useless without users' passwords.
- **Maintenance cron:** runs daily at 03:17 UTC. It purges tombstones older than 90 days and
  audit entries older than 180 days, and cleans up expired sessions and counters.
- **Upgrades:** pull, `pnpm install && pnpm build`, run the migrations for each environment,
  then deploy. Migrations are forward-only and always run before the deploy, both in CI and in
  the commands above.
- **Limits:** 1000 items per user, 8 KB per item, 200 changes per sync push.
