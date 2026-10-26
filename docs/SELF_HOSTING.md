# Deploying veilauth to Cloudflare

veilauth runs entirely on Cloudflare: one **Worker** serves both the API (`/api/v1/*`) and the
web app, from the same origin, and **D1** stores the encrypted vault. There is no separate Pages
project: the Worker's static assets are the web app. Everything fits in the Workers Free plan
for personal use.

There is one environment, production. Cloudflare builds and deploys it from GitHub on every
push to `main` (Workers Builds); GitHub Actions only runs CI and builds release files.

## 1. Create the D1 database

Dashboard → **Storage & Databases** → **D1 SQL Database** → **Create** → name it `veilauth` →
copy the **Database ID**.

## 2. Put the database id in `wrangler.jsonc`

Open `apps/worker/wrangler.jsonc` on GitHub → ✏️ edit → set `d1_databases[0].database_id`
to the id from step 1 → **Commit changes**. The id is not secret.

## 3. Generate the secrets (once)

On any machine with Node 22:

```sh
git clone https://github.com/nos486/veilauth.git && cd veilauth/apps/worker
node scripts/generate-secrets.mjs --print
```

It prints three values: `JWT_PRIVATE_JWK` (signs 15-minute access tokens), `FAKE_SALT_SECRET`
(fake prelogin salts, so nobody can tell which e-mails have accounts) and `IP_HASH_SECRET`
(pseudonymises IPs and e-mails in logs and counters). Paste them only into the dashboard in
step 5 and don't save them anywhere else. Never regenerate them later: a new `JWT_PRIVATE_JWK`
logs every device out, and a new `FAKE_SALT_SECRET` lets an observer tell real accounts from
fake ones.

## 4. Create the Worker from the repository

Dashboard → **Workers & Pages** → **Create** → **Import a repository** → pick `nos486/veilauth`:

| Field          | Value                                                             |
| -------------- | ----------------------------------------------------------------- |
| Project name   | `veilauth` (must match `name` in `wrangler.jsonc`)                |
| Root directory | `/`                                                               |
| Build command  | `corepack enable && pnpm install --frozen-lockfile && pnpm build` |
| Deploy command | `cd apps/worker && pnpm run deploy`                               |

Click **Deploy**. There is no migration step: the Worker creates its tables on the first request
and applies new migrations by itself after each update (D-051).

## 5. Add the secrets

Worker `veilauth` → **Settings** → **Variables and Secrets** → **Add**, type **Secret**, once
for each value from step 3. Then **Deployments** → **Retry build** (or push to `main`).

Keep plain variables such as `TURNSTILE_SITE_KEY` in `wrangler.jsonc`: a value edited in the
dashboard is overwritten by the next deploy. Secrets survive deploys.

## 6. Check it

Open `https://veilauth.<subdomain>.workers.dev/api/v1/time`. You should see `{"now":...}`. Then
open the root URL and create an account.

## Custom domain (recommended)

Worker `veilauth` → **Settings** → **Domains & Routes** → **Add** → **Custom domain** →
`vault.example.com`. Cloudflare issues the certificate. Then turn off the `workers.dev` route
on the same page so the app has a single origin.

## Updates

Every push to `main` rebuilds and redeploys. For manual-only deploys, turn off **Settings** →
**Build** → **Branch control** and use **Deployments** → **Retry build** when you want to ship.

## Turnstile (optional)

Turnstile is Cloudflare's CAPTCHA replacement; it stops scripts from mass-creating accounts. It
is off while `TURNSTILE_SITE_KEY` is empty (D-049). Without it, sign-up is still limited to 3
accounts per hour per IP. To turn it on: Dashboard → **Turnstile** → **Add widget** (hostname =
your domain, mode **Managed**), put the site key in `wrangler.jsonc` → `vars.TURNSTILE_SITE_KEY`,
and add the secret key as the secret `TURNSTILE_SECRET_KEY`.

## Android releases (signed APK and AAB)

Pushing a tag such as `v0.1.0` runs `release.yml`, which builds the signed Android app and
publishes a GitHub Release. Set these in GitHub → **Settings** → **Secrets and variables** →
**Actions**. Without them the release has no APK, and the workflow prints a warning.

| Name                        | Kind     | Value                                                                       |
| --------------------------- | -------- | --------------------------------------------------------------------------- |
| `ANDROID_KEYSTORE_BASE64`   | secret   | the release keystore, base64-encoded (see below)                            |
| `ANDROID_KEYSTORE_PASSWORD` | secret   | keystore password                                                           |
| `ANDROID_KEY_ALIAS`         | secret   | key alias, e.g. `veilauth`                                                  |
| `ANDROID_KEY_PASSWORD`      | secret   | key password                                                                |
| `PRODUCTION_URL`            | variable | your Worker's address, e.g. `https://vault.example.com`, built into the APK |

Create the keystore once, on your own machine, and keep an offline backup. **Every future
update must be signed with this same key**: the in-app updater and Android itself refuse an APK
signed with another key, so losing it means users have to uninstall and reinstall.

```sh
keytool -genkeypair -v -keystore veilauth-release.jks -alias veilauth \
  -keyalg RSA -keysize 4096 -validity 10000
base64 -w0 veilauth-release.jks   # paste the output into ANDROID_KEYSTORE_BASE64
```

Each release then contains `veilauth-<version>.apk` (GitHub flavor, with the in-app updater),
`veilauth-<version>-fdroid.apk` (no updater), `veilauth-<version>.aab`, `android-update.json`
(what the updater reads: version, file name, SHA-256) and the signing certificate's SHA-256 in
the release notes. Users can compare that fingerprint with
`apksigner verify --print-certs veilauth-<version>.apk`.

The app trusts the API host only with the certificate pins in `apps/android/app/build.gradle.kts`
(the root CAs Cloudflare uses). If your custom domain uses another CA, build with
`-Pveilauth.certPins=sha256/...` (or `none` to rely on the system trust store only).

## Troubleshooting

| Symptom                                                       | Fix                                                                                            |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Every request returns `{"code":"INTERNAL"}`                   | Workers Logs shows `missing_secrets` with the names to add under **Variables and Secrets**.    |
| The log says `D1_SCHEMA_MISSING`                              | The automatic migration failed; the `unhandled` log line next to it says why.                  |
| Build fails with `Couldn't find a D1 DB`                      | `database_id` in `wrangler.jsonc` is not your database's id (step 2).                          |
| Register fails with `TURNSTILE_REQUIRED` / `TURNSTILE_FAILED` | The widget hostname must match the app's domain, and both keys must belong to the same widget. |

## Local development

```sh
pnpm install && pnpm build                 # repo root
cd apps/worker
node scripts/generate-secrets.mjs --dev    # writes .dev.vars (git-ignored)
pnpm dev                                   # http://localhost:8787
```

Locally, D1 is simulated and Turnstile is off.

## Operations

- **Logs:** Dashboard → Workers → veilauth → **Logs** (Workers Logs is enabled). Only error
  class names and route paths are logged, never request data.
- **Backups:** D1 Time Travel restores the database to any minute in the last 30 days
  (`npx wrangler d1 time-travel restore veilauth --timestamp=...`). The data is
  ciphertext, so a backup is useless without users' passwords.
- **Maintenance cron:** runs daily at 03:17 UTC. It purges tombstones older than 90 days and
  audit entries older than 180 days, and cleans up expired sessions and counters.
- **Upgrades:** push to `main`. The new version applies pending D1 migrations (forward-only,
  each in one transaction) on its first request. To change the schema, add the next
  `apps/worker/migrations/NNNN_name.sql` and update `src/db/schema.ts`; `pnpm build` bundles it.
- **Limits:** 1000 items per user, 8 KB per item, 200 changes per sync push.
