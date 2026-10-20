import {
  type Bytes,
  concat,
  copyBytes,
  fromBase64Url,
  randomBytes,
  toBase64Url,
  utf8,
} from "./encoding.js";
import { CryptoError } from "./errors.js";

export const ENVELOPE_VERSION = 0x01;
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
export const ENVELOPE_OVERHEAD = 1 + NONCE_BYTES + TAG_BYTES;

/** GCM AAD = version ‖ UTF8(context) */
export function gcmAad(version: number, context: string): Bytes {
  return concat(Uint8Array.of(version), utf8(context));
}

/** @internal Fixed-nonce variant. Only `testing.ts` may expose this. */
export async function sealWithNonce(
  key: CryptoKey,
  plaintext: Uint8Array,
  context: string,
  nonce: Uint8Array,
): Promise<string> {
  if (nonce.length !== NONCE_BYTES) throw new CryptoError("INVALID_ENVELOPE");
  const iv = copyBytes(nonce);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: gcmAad(ENVELOPE_VERSION, context), tagLength: 128 },
    key,
    copyBytes(plaintext),
  );
  return toBase64Url(concat(Uint8Array.of(ENVELOPE_VERSION), iv, new Uint8Array(ct)));
}

/** Envelope(key, pt, ctx) with a fresh random nonce (spec/crypto.md §5). */
export async function seal(
  key: CryptoKey,
  plaintext: Uint8Array,
  context: string,
): Promise<string> {
  return sealWithNonce(key, plaintext, context, randomBytes(NONCE_BYTES));
}

export interface ParsedEnvelope {
  version: number;
  nonce: Bytes;
  /** ciphertext ‖ tag */
  body: Bytes;
}

export function parseEnvelope(envelope: string): ParsedEnvelope {
  let raw: Bytes;
  try {
    raw = fromBase64Url(envelope);
  } catch (e: unknown) {
    if (e instanceof CryptoError) throw new CryptoError("INVALID_ENVELOPE");
    throw e;
  }
  if (raw.length < ENVELOPE_OVERHEAD || raw[0] !== ENVELOPE_VERSION)
    throw new CryptoError("INVALID_ENVELOPE");
  return {
    version: ENVELOPE_VERSION,
    nonce: raw.slice(1, 1 + NONCE_BYTES),
    body: raw.slice(1 + NONCE_BYTES),
  };
}

/** Opens an envelope; any authentication failure is reported as DECRYPT_FAILED. */
export async function open(key: CryptoKey, envelope: string, context: string): Promise<Bytes> {
  const { version, nonce, body } = parseEnvelope(envelope);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: gcmAad(version, context), tagLength: 128 },
      key,
      body,
    );
    return new Uint8Array(pt);
  } catch (e: unknown) {
    if (e instanceof DOMException && e.name === "OperationError")
      throw new CryptoError("DECRYPT_FAILED");
    throw e;
  }
}
