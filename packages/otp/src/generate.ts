import { base32Decode } from "./base32.js";
import { OtpError } from "./errors.js";
import type { OtpAlgorithm, OtpParams } from "./types.js";
import { DEFAULT_PERIOD } from "./types.js";

const HASH: Record<OtpAlgorithm, string> = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };
const STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";

function counterBytes(counter: number): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new OtpError("INVALID_COUNTER");
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, BigInt(counter));
  return buf;
}

/** RFC 4226 dynamic truncation → 31-bit integer. */
async function truncated(
  secret: Uint8Array,
  counter: number,
  algorithm: OtpAlgorithm,
): Promise<number> {
  const key = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(secret),
    { name: "HMAC", hash: HASH[algorithm] },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes(counter)));
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const view = new DataView(mac.buffer, mac.byteOffset + offset, 4);
  return view.getUint32(0) & 0x7fffffff;
}

/** RFC 4226 HOTP. */
export async function hotp(
  secret: Uint8Array,
  counter: number,
  digits = 6,
  algorithm: OtpAlgorithm = "SHA1",
): Promise<string> {
  if (!Number.isInteger(digits) || digits < 1 || digits > 10) throw new OtpError("INVALID_DIGITS");
  const code = (await truncated(secret, counter, algorithm)) % 10 ** digits;
  return code.toString().padStart(digits, "0");
}

/** Time step for `timeMs` (unix ms). */
export function timeCounter(timeMs: number, period: number = DEFAULT_PERIOD): number {
  if (!Number.isFinite(timeMs) || timeMs < 0) throw new OtpError("INVALID_TIME");
  if (!Number.isInteger(period) || period < 1) throw new OtpError("INVALID_PERIOD");
  return Math.floor(timeMs / 1000 / period);
}

/** Seconds until the current code expires (1..period). */
export function secondsRemaining(timeMs: number, period: number = DEFAULT_PERIOD): number {
  const elapsed = Math.floor(timeMs / 1000) % period;
  return period - elapsed;
}

/** RFC 6238 TOTP with T0 = 0. */
export async function totp(
  secret: Uint8Array,
  timeMs: number,
  period: number = DEFAULT_PERIOD,
  digits = 6,
  algorithm: OtpAlgorithm = "SHA1",
): Promise<string> {
  return hotp(secret, timeCounter(timeMs, period), digits, algorithm);
}

/** Steam Guard: TOTP-SHA1 / 30 s, 5 characters from Steam's 26-letter alphabet. */
export async function steam(secret: Uint8Array, timeMs: number): Promise<string> {
  let code = await truncated(secret, timeCounter(timeMs, 30), "SHA1");
  let out = "";
  for (let i = 0; i < 5; i++) {
    out += STEAM_ALPHABET.charAt(code % 26);
    code = Math.floor(code / 26);
  }
  return out;
}

/** Code for a stored token. For HOTP the stored counter is used and `timeMs` is ignored. */
export async function generateCode(params: OtpParams, timeMs: number): Promise<string> {
  const secret = base32Decode(params.secret);
  try {
    switch (params.type) {
      case "totp":
        return await totp(secret, timeMs, params.period, params.digits, params.algorithm);
      case "hotp":
        return await hotp(secret, params.counter, params.digits, params.algorithm);
      case "steam":
        return await steam(secret, timeMs);
    }
  } finally {
    secret.fill(0);
  }
}
