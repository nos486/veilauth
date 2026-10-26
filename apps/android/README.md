# apps/android

Kotlin + Jetpack Compose. Package `app.zk2fa` (D-001), min SDK 26.

| Module        | Plugin  | What                                                                                   |
| ------------- | ------- | -------------------------------------------------------------------------------------- |
| `:core:otp`   | JVM     | HOTP/TOTP/Steam, `otpauth://`, Google Authenticator export decoder                     |
| `:core:crypto`| JVM     | Argon2id + HKDF (BouncyCastle), AES-GCM envelopes, JCS + padding, recovery words       |
| `:core:api`   | JVM     | models generated from `spec/api.openapi.yaml`, OkHttp client                           |
| `:core:vault` | JVM     | log-in, unlock, ciphertext store semantics, sync and conflicts                         |
| `:app`        | Android | Compose UI, Room, Keystore, biometrics, CameraX + ML Kit, WorkManager, updater         |

The core modules must pass `spec/test-vectors.json` and need no Android SDK:

```sh
./gradlew -Pveilauth.coreOnly=true test
```

The app needs the Android SDK (Android Studio, or `ANDROID_HOME`):

```sh
./gradlew :app:assembleGithubDebug -Pveilauth.apiBaseUrl=https://your-worker.example.com
```

`-Pveilauth.apiBaseUrl` picks the server, `-Pveilauth.certPins` overrides the certificate pins
(D-047). Regenerate the API models after changing the server schemas with
`pnpm --filter @zk2fa/shared kotlin`. Flavors: `github` (in-app updater, D-019) and `fdroid`.
Signed release builds come from `.github/workflows/release.yml` (docs/SELF_HOSTING.md, "Android releases").
