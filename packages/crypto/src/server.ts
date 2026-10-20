/**
 * Server-side helpers for the Worker (spec/crypto.md §4.1–4.2). WebCrypto PBKDF2/HMAC only.
 * Argon2 never runs on the server.
 */
import { type Bytes, constantTimeEqual, copyBytes, randomBytes, utf8 } from "./encoding.js";
import { normalizeEmail } from "./kdf.js";
import { AUTH_SALT_BYTES, KDF_SALT_BYTES, PBKDF2_ITERATIONS } from "./params.js";

export { constantTimeEqual, fromBase64Url, toBase64Url } from "./encoding.js";
export { normalizeEmail } from "./kdf.js";
export { CURRENT_KDF_VERSION, DEFAULT_KDF_PARAMS, KDF_ALG, PBKDF2_ITERATIONS } from "./params.js";

export function generateAuthSalt(): Bytes {
  return randomBytes(AUTH_SALT_BYTES);
}

/** authHash = PBKDF2-HMAC-SHA256(authKey, authSalt, 100000, 32). Also used for recoveryAuth. */
export async function computeAuthHash(
  authKey: Uint8Array,
  authSalt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS,
): Promise<Bytes> {
  const key = await crypto.subtle.importKey("raw", copyBytes(authKey), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: copyBytes(authSalt), iterations },
    key,
    256,
  );
  return new Uint8Array(bits);
}

/** Recomputes and compares in constant time. */
export async function verifyAuthHash(
  authKey: Uint8Array,
  authSalt: Uint8Array,
  expected: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS,
): Promise<boolean> {
  return constantTimeEqual(await computeAuthHash(authKey, authSalt, iterations), expected);
}

/** fakeSalt = HMAC-SHA256(FAKE_SALT_SECRET, NormEmail(email))[0..16] — prevents account enumeration. */
export async function fakeSalt(secret: Uint8Array, email: string): Promise<Bytes> {
  const key = await crypto.subtle.importKey(
    "raw",
    copyBytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, utf8(normalizeEmail(email)));
  return new Uint8Array(mac).slice(0, KDF_SALT_BYTES);
}
