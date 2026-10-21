# Deploying veilauth to Cloudflare

veilauth runs entirely on Cloudflare: one **Worker** serves the API (`/api/v1/*`) and the web
app's static files from the same origin, **D1** stores the encrypted vault, and the **Rate
Limiting** binding plus **Turnstile** protect the login endpoints. Everything fits in the Workers
Free plan for personal use. The Workers Paid plan ($5/month) gives you more D1 and CPU headroom.

There are three ways to deploy:

| Way                                                                                                           | Best for                                        | You need                                    |
| ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------- |
| **A. Manual, command line** (sections 1–6)                                                                    | full control, fastest                           | Node 22 + pnpm on your machine              |
| **B. Manual, Cloudflare dashboard only** ([section B](#b-manual-deploy-from-the-cloudflare-dashboard-no-cli)) | no local tooling; Cloudflare builds from GitHub | a browser (and Node once, to generate keys) |
| **C. Automatic, GitHub Actions** ([section C](#c-automatic-deploys-from-github-actions-recommended))          | push to `main` → staging, tag → production      | A or B done once, plus two GitHub secrets   |

## A. Manual deploy from the command line

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

To deploy only production, use `production` in place of `staging production` in step 2 and skip
the staging commands below.

### 1. Log in to Cloudflare

```sh
npx wrangler login      # opens a browser; or set CLOUDFLARE_API_TOKEN for CI
npx wrangler whoami     # note your Account ID
```

### 2. Create the D1 databases

```sh
node scripts/setup-cloudflare.mjs staging production
```

The script creates `veilauth-staging` and `veilauth-production` (if they don't exist yet) and
writes their ids into `wrangler.jsonc` in place of `REPLACE_WITH_*_D1_ID`. Commit that change:
database ids are not secret.

To do it by hand instead, run `npx wrangler d1 create veilauth-production` and paste the
`database_id` it prints into `env.production.d1_databases[0].database_id`.

### 3. Create a Turnstile widget (production)

1. Dashboard → **Turnstile** → **Add widget**.
2. Hostname: the domain you will serve veilauth on (for example `vault.example.com`, or
   `veilauth.<your-subdomain>.workers.dev`).
3. Widget mode: **Managed**.
4. Copy the **site key** into `wrangler.jsonc` → `env.production.vars.TURNSTILE_SITE_KEY`
   (it is public). Keep the **secret key** for step 4.

Staging uses Cloudflare's always-pass test keys, so automated tests can register accounts.

### 4. Set the secrets

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

To paste the secrets into the dashboard yourself instead, run
`node scripts/generate-secrets.mjs --print`.

Generate these **once per environment**. Rotating `JWT_PRIVATE_JWK` logs every device out.
Rotating `FAKE_SALT_SECRET` changes the fake salts, which lets an observer tell real accounts
from fake ones. The script never prints the values. They exist only in Cloudflare.

### 5. Apply the database migrations

```sh
pnpm db:migrate:staging
pnpm db:migrate:production
```

### 6. Deploy

```sh
pnpm deploy:staging
pnpm deploy:production
```

Wrangler prints the URL, for example `https://veilauth.<subdomain>.workers.dev`. Check it:

```sh
curl https://veilauth.<subdomain>.workers.dev/api/v1/time
# {"now":1792562498116}
```

## B. Manual deploy from the Cloudflare dashboard (no CLI)

Cloudflare **Workers Builds** pulls the repository from GitHub, builds it and deploys it. You do
everything in the browser. The only local step is generating the keys once.

### B1. Create the D1 database

Dashboard → **Storage & Databases** → **D1 SQL Database** → **Create** → name
`veilauth-production` → copy the **Database ID**.

### B2. Create a Turnstile widget

Same as [step 3](#3-create-a-turnstile-widget-production). Keep the site key and the secret key.

### B3. Put the ids in `wrangler.jsonc` (on GitHub)

Open `apps/worker/wrangler.jsonc` on GitHub → ✏️ edit:

- replace `REPLACE_WITH_PRODUCTION_D1_ID` with the Database ID from B1;
- replace `REPLACE_WITH_TURNSTILE_SITE_KEY` with the Turnstile site key.

**Commit changes.** Neither value is secret.

### B4. Generate the secrets (once)

On any machine with Node 22:

```sh
git clone https://github.com/nos486/veilauth.git && cd veilauth/apps/worker
node scripts/generate-secrets.mjs --print
```

This prints three values. Paste them only into the dashboard in B6 and don't save them anywhere
else.

### B5. Connect the repository and run the first build

Dashboard → **Workers & Pages** → **Create** → **Import a repository** → pick `nos486/veilauth`:

| Field          | Value                                                                                                                                      |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Project name   | `veilauth` (must match the production Worker name)                                                                                         |
| Root directory | `/`                                                                                                                                        |
| Build command  | `corepack enable && pnpm install --frozen-lockfile && pnpm build`                                                                          |
| Deploy command | `cd apps/worker && npx wrangler d1 migrations apply veilauth-production --remote --env production && npx wrangler deploy --env production` |

Click **Deploy**. The deploy command applies pending D1 migrations before every deploy.

> If the migration step fails with an authentication or permission error, go to the Worker →
> **Settings** → **Build** → **API token**, add **Account · D1 · Edit**, then **Retry build**.

### B6. Add the secrets

Worker `veilauth` → **Settings** → **Variables and Secrets** → **Add**. Set **Type** to
**Secret** for each of these:

- `JWT_PRIVATE_JWK`, `FAKE_SALT_SECRET`, `IP_HASH_SECRET` (from B4)
- `TURNSTILE_SECRET_KEY` (from B2)

Then click **Deploy**.

Keep the plain variables (`ENVIRONMENT`, `TURNSTILE_SITE_KEY`) in `wrangler.jsonc`. If you edit
them in the dashboard, the next deploy overwrites your change. Secrets survive deploys.

### B7. Check it

Open `https://veilauth.<subdomain>.workers.dev/api/v1/time` in a browser. You should see
`{"now":...}`.

### B8. Later updates

By default, every push to `main` rebuilds and redeploys. For manual-only deploys, turn off
**Settings** → **Build** → **Branch control** and use **Deployments** → **Retry build** when
you want to ship.

## C. Automatic deploys from GitHub Actions (recommended)

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

On the first run you don't need to do steps 2 and 4 of section A yourself. Each workflow creates
the D1 database if it is missing (and fills its id into its own copy of `wrangler.jsonc`), and
generates any missing `JWT_PRIVATE_JWK`, `FAKE_SALT_SECRET` and `IP_HASH_SECRET` inside
Cloudflare. Existing secrets are never replaced. For production you still set the Turnstile site
key in `wrangler.jsonc` and `TURNSTILE_SECRET_KEY` with `wrangler secret put` (step 3).

## Custom domain (recommended, A or B)

Dashboard → **Workers & Pages** → `veilauth` → **Settings** → **Domains & Routes** → **Add** →
**Custom domain** → `vault.example.com`. Cloudflare issues the certificate. Then turn off the
`workers.dev` route on the same page so the app has a single origin, and add the new domain to
the Turnstile widget's hostnames.

## Updating a manual (command-line) deploy

```sh
git pull
pnpm install && pnpm build          # repo root
cd apps/worker
pnpm db:migrate:production          # always migrate first
pnpm deploy:production
../../scripts/smoke-test.sh https://vault.example.com
```

## Troubleshooting

| Symptom                                                       | Fix                                                                                                              |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Every request returns `{"code":"INTERNAL"}`                   | A secret is missing. Check Variables and Secrets (or `npx wrangler secret list --env production`).               |
| Register fails with `TURNSTILE_REQUIRED` / `TURNSTILE_FAILED` | The widget hostname must match the app's domain, and the site key and secret key must belong to the same widget. |
| `no such table: users`                                        | The migrations have not been applied: `pnpm db:migrate:production`.                                              |
| `Couldn't find a D1 DB`                                       | `wrangler.jsonc` still contains `REPLACE_WITH_..._D1_ID`.                                                        |

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
