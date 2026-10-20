import { OtpError } from "./errors.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const LOOKUP: ReadonlyLookup = buildLookup();

type ReadonlyLookup = ReadonlyMap<string, number>;

function buildLookup(): ReadonlyLookup {
  const m = new Map<string, number>();
  for (let i = 0; i < ALPHABET.length; i++) m.set(ALPHABET.charAt(i), i);
  return m;
}

/** RFC 4648 base32 encode, upper-case, no padding. */
export function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET.charAt((buffer >>> (bits - 5)) & 31);
      bits -= 5;
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET.charAt((buffer << (5 - bits)) & 31);
  return out;
}

/**
 * Normalise user / URI supplied base32: strips spaces, hyphens and trailing `=`, upper-cases.
 * Throws INVALID_SECRET when the result is not canonical RFC 4648 base32.
 */
export function normalizeBase32(input: string): string {
  const s = input.replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase();
  base32Decode(s);
  return s;
}

/** Strict decode of canonical, unpadded, upper-case base32. Rejects impossible lengths and non-zero trailing bits. */
export function base32Decode(s: string): Uint8Array {
  const rem = s.length % 8;
  if (rem === 1 || rem === 3 || rem === 6) throw new OtpError("INVALID_SECRET");
  const out = new Uint8Array(Math.floor((s.length * 5) / 8));
  let buffer = 0;
  let bits = 0;
  let idx = 0;
  for (const ch of s) {
    const v = LOOKUP.get(ch);
    if (v === undefined) throw new OtpError("INVALID_SECRET");
    buffer = ((buffer << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out[idx++] = (buffer >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  if ((buffer & ((1 << bits) - 1)) !== 0) throw new OtpError("INVALID_SECRET");
  return out;
}
