# Threat model

## Assets

1. TOTP/HOTP/Steam secrets and their metadata (issuer, account, notes, folders, tags).
2. The master password, the recovery key and every key derived from them.
3. Session material (refresh tokens, access tokens).
4. Availability of the vault (the user must not lose tokens).

## Trust boundaries

```
 [ Android app ]──┐
                  ├── HTTPS ──> [ Cloudflare Worker ] ──> [ D1 ] [ KV / rate limits ]
 [ Web client  ]──┘                      │
   (JS served by the Worker)             └── serves the web client's static assets
```

Everything to the right of the HTTPS arrow is **untrusted for confidentiality**. It stores only
what `spec/crypto.md` §7 lists.

## Protected against

| Adversary                          | Why they learn nothing useful                                                                                                                                                               |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Full D1 dump / backup leak         | Items are AES-256-GCM under a vault key that is wrapped by an Argon2id-derived KEK (64 MiB, t=3). `authHash` is PBKDF2 over a 256-bit HKDF output, which reveals nothing about the KEK.     |
| Malicious DB admin modifying rows  | AAD binds every blob to user id, item id and kind: swapping, cross-user replay and kind confusion all fail. Wrapped keys are bound to the user id.                                          |
| Malicious server weakening the KDF | Clients enforce a KDF parameter floor (D-005).                                                                                                                                              |
| Account enumeration via prelogin   | Deterministic fake salt plus default params for unknown e-mails, same code path. Rate limited.                                                                                              |
| Network attacker                   | TLS (HSTS) everywhere; Android pins Cloudflare intermediates with a backup pin. Even with TLS broken, only ciphertext and `authKey` are visible, and `authKey` does not decrypt anything.   |
| Stolen Android phone, locked       | Vault key is wrapped by a Keystore key that requires Class 3 biometrics (StrongBox if available) and is invalidated on new enrolment. The cache holds ciphertext only. `allowBackup=false`. |
| Online password guessing           | Rate limits, exponential lockout, Turnstile after 3 failures.                                                                                                                               |
| Stolen refresh token               | Rotation with reuse detection revokes the whole token family. A password change rotates `security_stamp`, which kills every session.                                                        |

## Known limitations

- **Malicious web JS.** Whoever controls the Worker or the deploy pipeline can serve modified
  JavaScript that exfiltrates the password at the next unlock. This applies to all browser-based
  zero-knowledge apps. Mitigations: strict CSP + Trusted Types, SRI on every asset, reproducible
  builds with published hashes, automatic PWA updates that never apply silently while unlocked
  (D-018). Users at high risk should use the Android app, whose code only changes through APKs
  signed with the release key (D-019).
- **Rollback of single items.** The server can return an older ciphertext of the same item
  (an older revision of the same id/kind). AAD cannot bind the server-assigned revision. Clients
  keep the highest revision they have seen per item and flag regressions.
- **Metadata.** The server sees the number of items, their kinds, approximate sizes
  (256-byte buckets), edit times and device count.
- **Lost password + lost recovery key = lost data.** This follows from the design and the UI
  says so plainly at signup.

## Not protected

- A compromised client device while the vault is unlocked (root, malware, malicious browser
  extension, accessibility-service abuse).
- Weak master passwords chosen despite the strength meter. Argon2id only slows guessing.
- A user who copies codes into a compromised clipboard manager. Clips are marked sensitive and
  cleared after 30 s where the platform allows.

## Logging rule

No secret, password, key, token, ciphertext body or otpauth URI is ever logged, put in an error
message or included in a crash report, on any tier. Error types carry stable codes only.
