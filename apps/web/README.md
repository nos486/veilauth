# apps/web

The veilauth web client: React 18 + Vite + TypeScript PWA, served by the Worker from the same
origin as the API. See the root README for features and `docs/DECISIONS.md` (D-017, D-018,
D-035 to D-044) for the design choices.

```
src/
  crypto/     Web Worker (Argon2id, AES-GCM) + typed RPC; the vault key lives only there
  api/        fetch client: Zod-validated responses, refresh rotation serialised across tabs
  store/      IndexedDB cache (ciphertext only) and the in-memory UI store
  sync/       pull/push engine and conflict resolution
  app/        controller wiring UI ↔ crypto ↔ API ↔ cache; per-device settings
  screens/    one file per screen; components/ shared UI
  security/   Trusted Types policy, Zod jitless switch (CSP)
  i18n/en.json  every UI string
public/
  _headers    CSP and security headers for static assets
  turnstile.* the isolated Turnstile frame (D-036)
e2e/          Playwright: full sign-up → sync → password-change flow + D1 audit + axe
```

```sh
pnpm dev     # http://localhost:5173, proxies /api to a Worker on :8787
pnpm build   # dist/ with SRI and SHA256SUMS
pnpm test    # unit tests
pnpm e2e     # needs `pnpm build` and `playwright install chromium` first
```
