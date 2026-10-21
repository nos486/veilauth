# veilauth

A zero-knowledge TOTP/HOTP/Steam authenticator: Cloudflare Workers + D1 backend, a PWA, and a
native Android app. The server never sees your secrets, issuers, account names or master
password. Everything is encrypted on the device before upload.

> **Status: Phase 2 (web app) is done.** The crypto spec, shared test vectors, `otp` + `crypto`
> packages, the Cloudflare Worker API and the installable web app (PWA) are done and tested.
> The Android app (Phase 3) comes next.
>
> **Deploy your own:** [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) (Cloudflare Workers + D1, about 15 minutes).

## Repository layout

```
apps/
  worker/        Cloudflare Worker: Hono + Drizzle + Zod, D1 migrations      ✓
  web/           React 18 + Vite PWA, crypto in a Web Worker                 ✓
  android/       Kotlin, Compose, Hilt, Room, CameraX, ML Kit                (Phase 3)
packages/
  crypto/        @zk2fa/crypto: Argon2id, HKDF, key wrap, envelopes, items   ✓
  otp/           @zk2fa/otp: RFC 4226/6238, Steam, otpauth://, GA migration  ✓
  shared/        @zk2fa/shared: Zod API schemas → spec/api.openapi.yaml      ✓
spec/
  api.openapi.yaml   API contract (generated from packages/shared)
  crypto.md          normative crypto spec: formats, byte layouts, parameters
  test-vectors.json  source of truth every client must pass (generated)
  bip39-english.txt  pinned wordlist for recovery words
scripts/
  gen_test_vectors.py  independent Python reference implementation → test-vectors.json
docs/
  DECISIONS.md  THREAT_MODEL.md  SELF_HOSTING.md
  smoke-test.sh        post-deploy check used by the deploy workflows
.github/workflows/  ci.yml, codeql.yml, deploy-staging.yml (main → staging), release.yml (tag → production + GitHub Release)
```

## Local development

Requirements: Node 22, pnpm 10 (`corepack enable`), Python 3.11+ with `cryptography` ≥ 44
(only for regenerating test vectors).

```sh
pnpm install
pnpm test            # all packages, incl. Worker tests on a local D1 (workerd)
pnpm lint            # ESLint, strict type-checked rules
pnpm typecheck
pnpm format:check

pip install -r scripts/requirements.txt
pnpm vectors:check   # fails if spec/test-vectors.json drifted from the reference implementation
python3 -I scripts/gen_test_vectors.py   # regenerate after changing spec/crypto.md
pnpm --filter @zk2fa/shared openapi       # regenerate spec/api.openapi.yaml after changing schemas

# run the API and the built web app locally (http://localhost:8787)
pnpm build
cd apps/worker
node scripts/generate-secrets.mjs --dev && pnpm db:migrate:local && pnpm dev

# or hot-reload the web app (http://localhost:5173, proxies /api to the Worker on :8787)
pnpm --filter @zk2fa/web dev

# browser end-to-end test (starts its own Worker on :8799 with a fresh local D1)
pnpm build && pnpm --filter @zk2fa/web exec playwright install chromium
pnpm --filter @zk2fa/web e2e
```

## Web app

The Worker serves the PWA from the same origin as the API (`apps/web/dist`). Highlights:

- **Crypto in a Web Worker.** Argon2id and every encrypt/decrypt run in a dedicated worker with
  a typed message API. The vault key is a non-extractable `CryptoKey` that never leaves it.
- **Offline-first.** IndexedDB caches the same envelopes the server stores (never plaintext).
  Unlock works offline; edits queue locally and sync on unlock, on focus, every 60 s and right
  after a change. Conflicts keep both versions ([D-039](docs/DECISIONS.md)).
- **Locks itself.** Closing or reloading the tab locks; so do idle time (30 s to 15 min), 30 s
  in the background, the lock button and Ctrl/Cmd+L. Copied codes are cleared from the
  clipboard after 30 s.
- **Adds tokens** from the camera, an image file or a pasted screenshot, an `otpauth://` or
  Google Authenticator export link (multi-QR batches), or manual entry, with a live preview
  code and duplicate warnings.
- **Locked-down page.** Strict CSP with Trusted Types, no third-party scripts, fonts or
  analytics, Subresource Integrity on built assets and a published `SHA256SUMS`
  ([D-035–D-041](docs/DECISIONS.md)).
- **Updates like a website.** The service worker installs new builds in the background and
  switches over the next time the vault is locked ([D-018](docs/DECISIONS.md)).
- English-only UI, with every string in `apps/web/src/i18n/en.json`.

## Security model in one paragraph

Your master password is stretched on your device with Argon2id (64 MiB, 3 passes) and split
with HKDF into an **auth key** (sent to the server, which stores only a PBKDF2 hash of it) and a
**key-encryption key** that never leaves the device. A random **vault key** encrypts every item
with AES-256-GCM. The AAD binds each blob to its user, item id and kind, and the plaintext is
padded to 256-byte buckets. The vault key is stored on the server only in wrapped form: once
under your password KEK and once under a 24-word recovery key. Read the full details in
[spec/crypto.md](spec/crypto.md) and the limits in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Phases

| Phase | Scope                                                                                                                                   | Status  |
| ----- | --------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| 0     | Monorepo, crypto spec, test vectors, `otp` + `crypto` packages                                                                          | ✅ done |
| 1     | Worker: D1 schema, auth, sync, devices, rate limits, OpenAPI, staging deploy, release workflow                                          | ✅ done |
| 2     | Web MVP: signup + recovery key, unlock, vault CRUD, QR/URI/manual add, sync, auto-lock, PWA auto-update                                 | ✅ done |
| 3     | Android MVP: Kotlin crypto/otp on the shared vectors, biometric unlock, QR, sync, FLAG_SECURE, signed APK/AAB releases + in-app updater | next    |
| 4     | Importers, encrypted backup, trash, folders, icons, password change, recovery, account deletion                                         |         |
| 5     | Passkeys/PRF, widget, QS tile, Wear OS, Autofill, F-Droid flavor                                                                        |         |

### Phase 0 exit checklist

- [x] pnpm + Turborepo monorepo, TypeScript strict (`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`), ESLint `strictTypeChecked`, no `any`, no silent `catch`
- [x] `spec/crypto.md` with every byte layout and parameter
- [x] `spec/test-vectors.json` generated by an independent implementation (Python/OpenSSL) and checked for drift in CI
- [x] Published KATs pass: Argon2 reference, RFC 5869, RFC 4226 App. D, RFC 6238 App. B (SHA1/256/512), BIP39
- [x] `@zk2fa/otp`: HOTP, TOTP, Steam, otpauth:// parser/serializer, Google Authenticator migration (multi-QR)
- [x] `@zk2fa/crypto`: Argon2id (hash-wasm), HKDF/AES-GCM/PBKDF2/HMAC (WebCrypto), key wrap, recovery words, item envelopes, padding, tamper cases fail
- [x] `docs/DECISIONS.md`, `docs/THREAT_MODEL.md`
- [x] CI: lint, typecheck, tests, vector drift, dependency audit, CodeQL, secret scan

### Phase 1 exit checklist

- [x] D1 schema + forward-only migrations (`apps/worker/migrations`), Drizzle models
- [x] Auth: prelogin (fake salt), register, login, refresh rotation with reuse detection, logout, change password, two-step recovery, account deletion
- [x] Sync: revisioned pull with tombstones, batched push with per-item conflicts, race-safe revision bump, 1000 items / 8 KB / 200 per push limits, purge horizon → full resync
- [x] Devices list/revoke, `/time`, `/config`
- [x] Rate Limiting binding, D1 registration limit, per-(e-mail, IP) lockout, Turnstile escalation
- [x] Security headers on every API response, JSON errors with stable codes, no input echo, allowlisted logging
- [x] Daily cron: tombstones (90 d), audit log (180 d), expired sessions/counters
- [x] `spec/api.openapi.yaml` generated from Zod; CI fails on drift
- [x] Worker tests (Vitest in workerd + local D1): auth, refresh reuse, sync conflicts, rate limits, lockout, deletion, cron, zero-knowledge DB dump audit
- [x] Deploy guide ([docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)), setup/secret scripts, staging + release workflows with smoke test

### Phase 2 exit checklist

- [x] `apps/web`: React 18 + Vite + TypeScript strict, TanStack Query, Zustand, Tailwind, vite-plugin-pwa; no third-party fonts, CDNs or analytics
- [x] Crypto Web Worker with a typed RPC; vault key non-extractable and only in the worker
- [x] Sign-up with strength meter (zxcvbn), "no reset" warning, 24-word recovery key (download / print with QR), re-type 3 random words
- [x] Log-in (Turnstile when the server asks), offline unlock, lock on reload/close, idle, background and Ctrl/Cmd+L
- [x] Vault list: server-time-corrected codes, countdown ring, next-code preview in the last 5 s, tap to copy (clipboard cleared after 30 s), hide-until-tapped, search, favorites, HOTP next
- [x] Add by camera, image upload, pasted screenshot, `otpauth://` / Google Authenticator export link (multi-QR), manual entry; preview + duplicate check
- [x] Edit, trash (30-day purge), restore, delete; change password; devices list/revoke; delete account
- [x] Offline cache (ciphertext only) and sync with conflict copies ([D-039](docs/DECISIONS.md))
- [x] Strict CSP + Trusted Types, SRI on built assets, `SHA256SUMS`, website-style updates
- [x] Unit tests (crypto worker, sync conflicts on two devices, API client refresh/rotation, parsers) and the Playwright E2E from spec §8.1, with WCAG 2.1 AA checks (axe) and a CSP-violation check; E2E runs in CI
- [x] Worker serves the built app; smoke test checks the page CSP, SRI and service worker

### Acceptance criteria (spec §8.4)

- [x] Full D1 dump has no plaintext token data; zero-knowledge audit test passes. _Worker-level audit (`apps/worker/test/zero-knowledge.test.ts`) and the browser E2E, which scans every byte of the local D1 files (including the WAL) for the token's issuer, account, secret, both passwords and the recovery words._
- [ ] Web and Android derive identical keys and decrypt each other's items. _The shared vectors exist; the cross-client test comes in Phase 3._
- [x] Codes match Google Authenticator within /time-corrected drift. _RFC 4226/6238 vectors pass; the E2E compares the web app's code with an independent computation; the web clock is corrected with `/time`._
- [ ] Biometric unlock works offline; new fingerprint forces password (Phase 3)
- [x] Password change logs out other devices and keeps tokens. _E2E: browser B is sent to log-in on its next sync, the old password is refused, the new one shows the same token._
- [ ] Recovery key restores access. _Crypto and server flow are tested; the recovery UI comes in Phase 4._
- [x] Offline edits on two devices never lose a token (web). _`apps/web/test/sync.test.ts`; Android joins in Phase 3._
- [ ] Argon2id unlock < 1.5 s on a mid-range 2021 Android phone (Phase 3). _Web: Argon2id runs in a Web Worker, so the UI never blocks._
- [x] Accessibility ≥ 90 and no CSP violations. _The E2E runs axe-core (Lighthouse's accessibility engine) with the WCAG 2.1 AA rules on every screen in light and dark mode with zero violations, and fails on any CSP or Trusted Types violation. Lighthouse 12 no longer has a PWA category; installability comes from the manifest and service worker._
- [x] README covers local dev, self-hosting ([docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)) and the security model.
