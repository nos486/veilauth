# zk2fa cryptographic specification — v1

Status: **normative**. Every client (web, Android) and the Worker MUST implement exactly
what is written here. `spec/test-vectors.json` is generated from this document by an
independent reference implementation (`scripts/gen_test_vectors.py`, Python `cryptography`)
and every implementation MUST pass it byte for byte.

Key words MUST / MUST NOT / SHOULD are used as in RFC 2119.

## 0. Conventions

| Notation   | Meaning                                                                                                                                                                                         |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `a ‖ b`    | byte concatenation                                                                                                                                                                              |
| `UTF8(s)`  | UTF-8 encoding of string `s`, no BOM                                                                                                                                                            |
| `B64U(x)`  | base64url (RFC 4648 §5) **without** `=` padding. Decoders MUST reject padding, whitespace and characters outside `[A-Za-z0-9_-]`, and MUST reject non-canonical trailing bits.                  |
| `HEX(x)`   | lowercase hex (test vectors only)                                                                                                                                                               |
| `u32be(n)` | 4-byte big-endian unsigned integer                                                                                                                                                              |
| `id`       | UUIDv7 in canonical lowercase hyphenated form, regex `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`. Implementations MUST reject anything else before building an AAD. |

All random bytes MUST come from a CSPRNG (`crypto.getRandomValues`, `SecureRandom`).

## 1. Primitives (closed list)

| Purpose              | Primitive                                                    | Web          | Android                              | Worker    |
| -------------------- | ------------------------------------------------------------ | ------------ | ------------------------------------ | --------- |
| Password KDF         | Argon2id v1.3 (0x13)                                         | hash-wasm    | libsodium `crypto_pwhash` / argon2kt | **never** |
| Key derivation       | HKDF-SHA256 (RFC 5869)                                       | WebCrypto    | Tink `Hkdf`                          | WebCrypto |
| AEAD                 | AES-256-GCM, 96-bit nonce, 128-bit tag                       | WebCrypto    | `AES/GCM/NoPadding`                  | —         |
| Server password hash | PBKDF2-HMAC-SHA256                                           | —            | —                                    | WebCrypto |
| MAC                  | HMAC-SHA256                                                  | —            | —                                    | WebCrypto |
| Recovery words       | BIP39 English word encoding of 32 bytes (checksum = SHA-256) | @scure/bip39 | own encoder + wordlist               | —         |
| OTP                  | HMAC-SHA1/256/512                                            | WebCrypto    | `javax.crypto.Mac`                   | —         |

No other primitive may be introduced without a new version of this document.

## 2. Password and email normalisation

- `NormPassword(pw) = UTF8(NFKC(pw))`. No trimming, no case folding. Empty password is
  rejected by the UI (minimum length and zxcvbn score are UI policy, not crypto).
- `NormEmail(e) = toLowerCase(NFKC(trim(e)))` using locale-independent Unicode lower-casing
  (JS `toLowerCase()`, Kotlin `lowercase(Locale.ROOT)`). Used for the fake-salt HMAC and for
  storage; D1 additionally uses `COLLATE NOCASE`.

## 3. KDF parameters

Stored per user as `kdf_alg = "argon2id"`, `kdf_params = JCS({"m":<KiB>,"p":<lanes>,"t":<passes>})`,
`kdf_salt` = 16 random bytes, `kdf_version` integer.

| kdf_version | m (KiB)        | t   | p   | output   |
| ----------- | -------------- | --- | --- | -------- |
| 1           | 65536 (64 MiB) | 3   | 1   | 32 bytes |

Clients MUST validate params returned by `prelogin` **before** running the KDF
(defence against a malicious server downgrading the KDF):

- `kdf_alg` MUST be `"argon2id"`.
- `65536 ≤ m ≤ 262144`, `3 ≤ t ≤ 16`, `p = 1` (libsodium only supports p=1).
- salt length MUST be exactly 16 bytes.
- Anything else → abort with `KDF_PARAMS_REJECTED`; never fall back.

## 4. Key hierarchy

```
masterKey   = Argon2id(pwd = NormPassword(pw), salt = kdf_salt, m, t, p, len = 32)
                (no secret, no associated data)
authKey     = HKDF-SHA256(IKM = masterKey, salt = <empty>, info = UTF8("zk2fa/v1/auth"), L = 32)
kek         = HKDF-SHA256(IKM = masterKey, salt = <empty>, info = UTF8("zk2fa/v1/kek"),  L = 32)
```

- HKDF salt is the empty string, which RFC 5869 §2.2 defines as `HashLen` zero bytes.
  WebCrypto: `salt: new Uint8Array(0)`. Tink: `Hkdf.computeHkdf("HMACSHA256", ikm, new byte[0], info, 32)`.
- `masterKey` is wiped right after `authKey` and `kek` are derived. `kek` is imported as a
  non-extractable AES-GCM key on web.
- `authKey` is sent to the server (base64url) on register / login / change-password and is
  wiped after the request.

### 4.1 Server-side auth hash (Worker)

```
authSalt = 16 random bytes (per user, regenerated on every password change)
authHash = PBKDF2-HMAC-SHA256(password = authKey, salt = authSalt, c = 100000, dkLen = 32)
```

Verification recomputes `authHash` and compares in constant time. The recovery auth hash
(`recovery_auth_hash`, `recovery_auth_salt`) uses the identical construction with
`recoveryAuth` in place of `authKey`. 100 000 is also the Workers PBKDF2 iteration ceiling; the
real brute-force cost lives in the client-side Argon2id.

### 4.2 Fake prelogin salt (unknown e-mail)

```
fakeSalt = HMAC-SHA256(key = FAKE_SALT_SECRET, msg = UTF8(NormEmail(email)))[0..16]
```

`FAKE_SALT_SECRET` is ≥ 32 random bytes in `wrangler secret`, base64url encoded. The fake
response uses `kdf_version = 1` params, so it is indistinguishable from a real account created
with default params. Prelogin MUST take the same code path (HMAC computed for every request).

### 4.3 Vault key

```
vaultKey        = 32 random bytes, generated once at signup, never changes
wrappedVaultKey = Envelope(kek, vaultKey, AAD_VK(userId))
AAD_VK(userId)  = "zk2fa/v1/vk|" ‖ userId
```

A password change re-derives `kek'` from the new password and stores
`Envelope(kek', vaultKey, AAD_VK(userId))`; the vault itself is not re-encrypted.

### 4.4 Recovery key

```
recoveryKey          = 32 random bytes, generated at signup and after every recovery
recoveryWords        = BIP39-English(recoveryKey)               -- 24 words
recoveryKek          = HKDF-SHA256(recoveryKey, salt = <empty>, info = UTF8("zk2fa/v1/recovery-kek"),  32)
recoveryAuth         = HKDF-SHA256(recoveryKey, salt = <empty>, info = UTF8("zk2fa/v1/recovery-auth"), 32)
recoveryWrappedVK    = Envelope(recoveryKek, vaultKey, AAD_RVK(userId))
AAD_RVK(userId)      = "zk2fa/v1/rvk|" ‖ userId
recovery_auth_hash   = PBKDF2-HMAC-SHA256(recoveryAuth, recovery_auth_salt, 100000, 32)
```

BIP39 is used **only as an encoding**: 256 bits of entropy + first 8 bits of
`SHA-256(entropy)` as checksum = 264 bits = 24 × 11-bit indexes into
`spec/bip39-english.txt` (SHA-256 of the file:
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`). The BIP39 seed
(PBKDF2-HMAC-SHA512 with "mnemonic") is **not** used. Words are joined with a single ASCII
space. Decoders lower-case, trim and collapse whitespace, then MUST verify the checksum.

## 5. Envelope (all AES-GCM ciphertext)

```
Envelope(key, pt, ctx) = B64U( version ‖ nonce ‖ GCM_ct ‖ tag )

offset  size  field
0       1     version = 0x01
1       12    nonce   (fresh CSPRNG bytes per encryption, never reused)
13      n     GCM ciphertext (n = |pt|)
13+n    16    GCM tag

GCM AAD = version ‖ UTF8(ctx)        -- the version byte is authenticated too
GCM key = 32-byte key (AES-256)
```

- Minimum decoded length is 29 bytes (empty plaintext). Decoders MUST reject a version other
  than `0x01` before attempting decryption, and MUST surface any GCM failure as a single
  `DECRYPT_FAILED` error without distinguishing causes.
- `ctx` strings are ASCII, built only from fixed prefixes, validated `id`s and the closed `kind`
  enum, so the separator `|` cannot be injected.

| Blob                                 | Key         | ctx                                                                               |
| ------------------------------------ | ----------- | --------------------------------------------------------------------------------- |
| wrapped vault key                    | kek         | `zk2fa/v1/vk\|{userId}`                                                           |
| recovery-wrapped vault key           | recoveryKek | `zk2fa/v1/rvk\|{userId}`                                                          |
| vault item (token, folder, settings) | vaultKey    | `zk2fa/v1/item\|{userId}\|{itemId}\|{kind}`, kind ∈ `token`, `folder`, `settings` |
| device name                          | vaultKey    | `zk2fa/v1/device\|{userId}\|{deviceId}`                                           |
| encrypted backup file (§9)           | backupKey   | `zk2fa/v1/backup\|{B64U(backupSalt)}`                                             |

A wrapped key is always 1 + 12 + 32 + 16 = **61 bytes** (82 base64url characters).

## 6. Vault item plaintext

### 6.1 Canonical JSON (JCS)

Item plaintext is serialised with RFC 8785 JSON Canonicalization Scheme restricted to the
types used here: objects (keys sorted by UTF-16 code units — all our keys are ASCII), arrays,
strings, `true`/`false`/`null`, and **integers** in `[-(2^53-1), 2^53-1]`. Floats are forbidden.
Strings escape only `"`, `\`, and U+0000–U+001F (`\b \t \n \f \r`, others `\u00xx` lowercase);
all other characters, including non-ASCII, are emitted as raw UTF-8. Lone surrogates are
rejected. (JS: `JSON.stringify` with sorted keys produces exactly this for these types.)

Canonicalisation exists so that test vectors are byte-identical across clients; decoders accept
any valid JSON.

### 6.2 Padding (hides item length)

```
padded = u32be(len(json)) ‖ json ‖ 0x00 × k
k      = smallest value ≥ 0 such that len(padded) is a multiple of 256
```

Unpadding MUST check `4 + len ≤ len(padded)`, `len(padded) % 256 == 0`, and that every padding
byte is `0x00`; otherwise `DECRYPT_FAILED`.

Limits: an item blob is at most 8192 base64url characters = 6144 bytes, so
`len(padded) ≤ 5888` (23 buckets) and `len(json) ≤ 5884`. Encoders MUST refuse larger items.

### 6.3 Token item (`kind = "token"`)

All keys are always present (no optional keys), so the canonical form is stable.
Unknown keys MUST be preserved by clients on round-trip (forward compatibility).

| key         | type           | rule                                                         |
| ----------- | -------------- | ------------------------------------------------------------ |
| `type`      | string         | `"totp"` \| `"hotp"` \| `"steam"`                            |
| `issuer`    | string         | ≤ 256 UTF-16 code units, may be empty                        |
| `account`   | string         | ≤ 256 UTF-16 code units, may be empty                        |
| `secret`    | string         | RFC 4648 base32, upper-case, no padding, 1–128 decoded bytes |
| `algorithm` | string         | `"SHA1"` \| `"SHA256"` \| `"SHA512"` (steam: `"SHA1"`)       |
| `digits`    | int            | 6–8 for totp/hotp, 5 for steam                               |
| `period`    | int            | 1–86400 seconds (hotp: stored, ignored; default 30)          |
| `counter`   | int            | 0 – 2^53-1 (totp/steam: 0)                                   |
| `iconId`    | string \| null | id from the bundled icon pack                                |
| `folderId`  | string \| null | folder item `id`                                             |
| `tags`      | string[]       | each ≤ 64 UTF-16 code units, ≤ 32 tags                       |
| `notes`     | string         | ≤ 2048 UTF-16 code units                                     |
| `favorite`  | bool           | pinned to top                                                |
| `createdAt` | int            | unix ms                                                      |
| `trashedAt` | int \| null    | unix ms when moved to trash, `null` otherwise (30-day trash) |

### 6.4 Folder item (`kind = "folder"`)

`{"name": string ≤ 128 UTF-16 code units, "createdAt": int}` (+ preserved unknown keys).

### 6.5 Settings item (`kind = "settings"`)

Exactly one per user. JSON object, schema owned by the clients (sort order, auto-lock,
hide-codes, theme…). Same envelope and padding rules.

## 7. Server knowledge

The server stores and sees: e-mail, KDF params + salt, `authHash`/`authSalt`, the two wrapped
vault keys, the recovery auth hash/salt, item ids, kinds, revisions, timestamps, deleted flags,
ciphertext sizes rounded to 256-byte buckets, device platform and IP-hash in the audit log.
It never sees the password, `masterKey`, `kek`, `vaultKey`, `recoveryKey`, `recoveryKek` or any
item field.

## 8. Test vectors

`spec/test-vectors.json` sections:

| section              | checks                                                                                        |
| -------------------- | --------------------------------------------------------------------------------------------- |
| `argon2id.reference` | raw Argon2id against the reference implementation KAT                                         |
| `keyHierarchy`       | NFKC → Argon2id → HKDF auth/kek → PBKDF2 authHash → wrapped vault key (fixed nonce)           |
| `hkdf`               | raw HKDF-SHA256 outputs                                                                       |
| `fakeSalt`           | e-mail normalisation + HMAC truncation                                                        |
| `recovery`           | entropy ↔ 24 words, recoveryKek, recoveryAuth, recovery auth hash, recovery-wrapped vault key |
| `padding`            | JCS + padding bytes                                                                           |
| `items`              | full item encryption with fixed nonce: canonical JSON, padded length, envelope                |
| `tamper`             | envelopes / contexts that MUST fail to decrypt                                                |
| `invalidEnvelopes`   | malformed encodings that MUST be rejected before decryption                                   |
| `kdfParamsRejected`  | prelogin params that MUST be refused                                                          |
| `backup`             | backup files with fixed salt and nonce, byte for byte; files that MUST be rejected            |
| `otp.*`              | RFC 4226, RFC 6238 (SHA1/256/512), Steam, otpauth:// parsing, otpauth-migration:// decoding   |

Fixed nonces exist **only** in test vectors. Production code paths MUST NOT accept a
caller-supplied nonce.

## 9. Encrypted backup file

A backup is a file the user downloads and keeps. It is protected by a **backup password** the
user chooses at export time and is independent of the account: it holds no user id and no
account key, so it restores into the same account or any other one.

```
backupSalt  = 16 random bytes (fresh for every file)
backupMK    = Argon2id(pwd = NormPassword(backupPassword), salt = backupSalt, kdf_version 1 params)
backupKey   = HKDF-SHA256(IKM = backupMK, salt = <empty>, info = UTF8("zk2fa/v1/backup"), L = 32)
contents    = JCS({"exportedAt": <unix ms>, "tokens": [<token item §6.3>, …]})
data        = Envelope(backupKey, pad(contents), "zk2fa/v1/backup|" ‖ B64U(backupSalt))
file        = JCS({"format": "veilauth-backup", "version": 1,
                   "kdf": {"alg": "argon2id", "params": {"m":…,"p":…,"t":…}, "salt": B64U(backupSalt)},
                   "data": data})
```

- `pad` is §6.2 without the item size limit; encoders MUST refuse a padded size above 8 MiB and
  more than 1000 tokens (the vault limit). `backupMK` is wiped after HKDF.
- The salt is in the AAD, so `data` cannot be moved under another file's KDF header.
- Decoders MUST: reject a file over 12 MiB characters, any `format` other than
  `"veilauth-backup"` or `version` other than `1`, and a missing or mistyped field with
  `INVALID_BACKUP`; validate `kdf` with the §3 rules (`KDF_PARAMS_REJECTED`) **before** running
  Argon2id; report any GCM failure (wrong password or tampering) as `DECRYPT_FAILED`; then
  validate every token with §6.3, unknown keys preserved.
- Tokens in the trash are not exported. Folder items are not part of version 1; a restoring
  client clears `folderId` and `trashedAt`, gives every token a fresh item id, and skips tokens
  already in the vault (same issuer, account and secret).
