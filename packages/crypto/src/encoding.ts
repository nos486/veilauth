import { CryptoError } from "./errors.js";

/** Byte array backed by a plain ArrayBuffer (what WebCrypto accepts). */
export type Bytes = Uint8Array<ArrayBuffer>;

const B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64U_LOOKUP = new Map<string, number>(
  Array.from({ length: 64 }, (_, i) => [B64U.charAt(i), i]),
);

/** base64url without padding (spec/crypto.md §0). */
export function toBase64Url(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out +=
      B64U.charAt(n >>> 18) +
      B64U.charAt((n >>> 12) & 63) +
      B64U.charAt((n >>> 6) & 63) +
      B64U.charAt(n & 63);
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] ?? 0) << 16;
    out += B64U.charAt(n >>> 18) + B64U.charAt((n >>> 12) & 63);
  } else if (rest === 2) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8);
    out += B64U.charAt(n >>> 18) + B64U.charAt((n >>> 12) & 63) + B64U.charAt((n >>> 6) & 63);
  }
  return out;
}

/** Strict base64url decode: no padding, no whitespace, canonical trailing bits. */
export function fromBase64Url(s: string): Bytes {
  if (s.length % 4 === 1) throw new CryptoError("INVALID_ENCODING");
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let idx = 0;
  for (const ch of s) {
    const v = B64U_LOOKUP.get(ch);
    if (v === undefined) throw new CryptoError("INVALID_ENCODING");
    buffer = ((buffer << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      out[idx++] = (buffer >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  if ((buffer & ((1 << bits) - 1)) !== 0) throw new CryptoError("INVALID_ENCODING");
  return out;
}

export function utf8(s: string): Bytes {
  return new TextEncoder().encode(s);
}

const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

export function fromUtf8(bytes: Uint8Array): string {
  try {
    return strictUtf8.decode(bytes);
  } catch (e: unknown) {
    if (e instanceof TypeError) throw new CryptoError("INVALID_ENCODING");
    throw e;
  }
}

export function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Copies into a fresh ArrayBuffer-backed array (normalises SharedArrayBuffer / subarray views). */
export function copyBytes(bytes: Uint8Array): Bytes {
  return new Uint8Array(bytes);
}

/** Constant-time equality for equal-length inputs; length mismatch returns false immediately (lengths are public). */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Best-effort wipe of key material held in JS memory. */
export function wipe(...arrays: (Uint8Array | undefined)[]): void {
  for (const a of arrays) a?.fill(0);
}

export function randomBytes(n: number): Bytes {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}
