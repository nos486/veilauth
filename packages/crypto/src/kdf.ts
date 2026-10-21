import { argon2id } from "hash-wasm";
import { type Bytes, copyBytes, utf8, wipe } from "./encoding.js";
import { normalizePassword } from "./normalize.js";
import { type KdfParams, KEY_BYTES, validateKdfParams } from "./params.js";

export const INFO_AUTH = "zk2fa/v1/auth";
export const INFO_KEK = "zk2fa/v1/kek";
export const INFO_RECOVERY_KEK = "zk2fa/v1/recovery-kek";
export const INFO_RECOVERY_AUTH = "zk2fa/v1/recovery-auth";

/** Raw Argon2id (no parameter policy). Prefer {@link deriveMasterKey}. */
export async function argon2idRaw(
  password: Uint8Array,
  salt: Uint8Array,
  params: KdfParams,
  length: number = KEY_BYTES,
): Promise<Bytes> {
  const out = await argon2id({
    password,
    salt,
    parallelism: params.p,
    iterations: params.t,
    memorySize: params.m,
    hashLength: length,
    outputType: "binary",
  });
  return copyBytes(out);
}

/** masterKey = Argon2id(NFKC(password), salt, params) after validating params (spec/crypto.md §3–4). */
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params: KdfParams,
  alg = "argon2id",
): Promise<Bytes> {
  const validated = validateKdfParams(alg, params, salt);
  const pw = normalizePassword(password);
  try {
    return await argon2idRaw(pw, salt, validated);
  } finally {
    wipe(pw);
  }
}

/** HKDF-SHA256 with empty salt (spec/crypto.md §4). */
export async function hkdfSha256(
  ikm: Uint8Array,
  info: string,
  length: number = KEY_BYTES,
): Promise<Bytes> {
  const key = await crypto.subtle.importKey("raw", copyBytes(ikm), "HKDF", false, [
    "deriveBits",
    "deriveKey",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(info) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** HKDF directly into a non-extractable AES-256-GCM key, so the raw KEK never exists in JS memory. */
export async function hkdfToAesKey(ikm: Uint8Array, info: string): Promise<CryptoKey> {
  const key = await crypto.subtle.importKey("raw", copyBytes(ikm), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(info) },
    key,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
  );
}

export interface DerivedLoginKeys {
  /** sent to the server; wipe after use */
  authKey: Bytes;
  /** non-extractable; wraps / unwraps the vault key */
  kek: CryptoKey;
}

/** password → masterKey → {authKey, kek}; masterKey is wiped. */
export async function deriveLoginKeys(
  password: string,
  salt: Uint8Array,
  params: KdfParams,
  alg = "argon2id",
): Promise<DerivedLoginKeys> {
  const masterKey = await deriveMasterKey(password, salt, params, alg);
  try {
    const [authKey, kek] = await Promise.all([
      hkdfSha256(masterKey, INFO_AUTH),
      hkdfToAesKey(masterKey, INFO_KEK),
    ]);
    return { authKey, kek };
  } finally {
    wipe(masterKey);
  }
}
