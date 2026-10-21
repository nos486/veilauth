/**
 * Server-side helpers for the Worker (spec/crypto.md §4.1–4.2). WebCrypto PBKDF2/HMAC only.
 * Argon2 never runs on the server.
 */
import {
  type Bytes,
  constantTimeEqual,
  copyBytes,
  fromBase64Url,
  randomBytes,
  utf8,
} from "./encoding.js";
import { ENVELOPE_OVERHEAD, ENVELOPE_VERSION } from "./envelope.js";
import { MAX_BLOB_CHARS, PAD_BUCKET } from "./item.js";
import { normalizeEmail } from "./normalize.js";
import { AUTH_SALT_BYTES, KDF_SALT_BYTES, PBKDF2_ITERATIONS } from "./params.js";

export { constantTimeEqual, fromBase64Url, toBase64Url } from "./encoding.js";
export { normalizeEmail } from "./normalize.js";
export {
  CURRENT_KDF_VERSION,
  DEFAULT_KDF_PARAMS,
  KDF_ALG,
  KDF_SALT_BYTES,
  type KdfParams,
  PBKDF2_ITERATIONS,
  validateKdfParams,
} from "./params.js";
export { CryptoError } from "./errors.js";

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

/**
 * Structural check of an envelope the server stores but cannot decrypt: strict base64url, version 1,
 * and for vault items a padded length (multiple of 256 bytes), so clients cannot leak exact sizes.
 */
export function isWellFormedEnvelope(
  envelope: string,
  options: { padded: boolean; maxChars?: number },
): boolean {
  if (envelope.length > (options.maxChars ?? MAX_BLOB_CHARS)) return false;
  let raw: Bytes;
  try {
    raw = fromBase64Url(envelope);
  } catch (e: unknown) {
    if (e instanceof Error) return false;
    throw e;
  }
  if (raw.length < ENVELOPE_OVERHEAD || raw[0] !== ENVELOPE_VERSION) return false;
  return (
    !options.padded ||
    ((raw.length - ENVELOPE_OVERHEAD) % PAD_BUCKET === 0 && raw.length > ENVELOPE_OVERHEAD)
  );
}
