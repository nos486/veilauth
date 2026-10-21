-- veilauth initial schema (build spec §5.1). All ids are UUIDv7 text, timestamps are integer ms.
-- The server stores only ciphertext, wrapped keys and hashes (spec/crypto.md §7).

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email_verified INTEGER NOT NULL DEFAULT 0,
  kdf_alg TEXT NOT NULL,
  kdf_params TEXT NOT NULL,
  kdf_salt BLOB NOT NULL,
  kdf_version INTEGER NOT NULL,
  auth_hash BLOB NOT NULL,
  auth_salt BLOB NOT NULL,
  wrapped_vault_key TEXT NOT NULL,
  recovery_wrapped_vault_key TEXT NOT NULL,
  recovery_auth_hash BLOB NOT NULL,
  recovery_auth_salt BLOB NOT NULL,
  vault_revision INTEGER NOT NULL DEFAULT 0,
  -- highest revision of a purged tombstone; clients syncing from below it must do a full resync
  tombstone_horizon INTEGER NOT NULL DEFAULT 0,
  security_stamp TEXT NOT NULL,          -- rotated on password change / recovery: kills all sessions
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name_enc TEXT,                          -- device name, encrypted with the vault key
  platform TEXT NOT NULL CHECK (platform IN ('web','android')),
  refresh_hash BLOB NOT NULL,             -- SHA-256 of the current refresh token
  refresh_family TEXT NOT NULL,           -- one family per login; reuse of a rotated token revokes it
  refresh_expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX idx_devices_user ON devices(user_id);
CREATE UNIQUE INDEX idx_devices_refresh ON devices(refresh_hash);

-- Rotated (already used) refresh tokens, kept until they would have expired, for reuse detection.
CREATE TABLE refresh_history (
  token_hash BLOB PRIMARY KEY,
  family TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX idx_refresh_history_expiry ON refresh_history(expires_at);

CREATE TABLE vault_items (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('token','folder','settings')),
  blob TEXT,                              -- NULL when deleted (tombstone)
  revision INTEGER NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_items_user_rev ON vault_items(user_id, revision);

CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_id TEXT,
  event TEXT NOT NULL,
  ip_hash TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_audit_user ON audit_log(user_id, created_at);
CREATE INDEX idx_audit_created ON audit_log(created_at);

-- Fixed-window counters for hourly limits, login lockout and Turnstile escalation.
-- Keys contain only HMAC'd e-mail / IP values, never plaintext.
CREATE TABLE counters (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start INTEGER NOT NULL,
  locked_until INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);
CREATE INDEX idx_counters_expiry ON counters(expires_at);
