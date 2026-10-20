import { base32Decode, normalizeBase32 } from "./base32.js";
import { OtpError } from "./errors.js";
import type { OtpAlgorithm, OtpParams, OtpType } from "./types.js";
import {
  DEFAULT_DIGITS,
  DEFAULT_PERIOD,
  MAX_PERIOD,
  MAX_SECRET_BYTES,
  MIN_SECRET_BYTES,
  STEAM_DIGITS,
} from "./types.js";

const OTPAUTH_RE = /^otpauth:\/\/([^/?#]*)\/?([^?#]*)(?:\?([^#]*))?(?:#.*)?$/is;
const STEAM_RE = /^steam:\/\/([^/?#]+)\/?$/i;
const UINT_RE = /^\d+$/;

function decode(component: string): string {
  try {
    return decodeURIComponent(component);
  } catch (e: unknown) {
    if (e instanceof URIError) throw new OtpError("INVALID_URI", "malformed percent-encoding");
    throw e;
  }
}

function parseQuery(query: string): Map<string, string> {
  const params = new Map<string, string>();
  for (const part of query.split("&")) {
    if (part === "") continue;
    const eq = part.indexOf("=");
    const rawKey = eq === -1 ? part : part.slice(0, eq);
    const rawValue = eq === -1 ? "" : part.slice(eq + 1);
    const key = decode(rawKey.replace(/\+/g, " ")).toLowerCase();
    if (!params.has(key)) params.set(key, decode(rawValue.replace(/\+/g, " ")));
  }
  return params;
}

/** Validates and normalises a base32 secret; throws INVALID_SECRET / MISSING_SECRET. */
export function parseSecret(raw: string | undefined): string {
  if (raw === undefined || raw.trim() === "") throw new OtpError("MISSING_SECRET");
  const secret = normalizeBase32(raw);
  const length = base32Decode(secret).length;
  if (length < MIN_SECRET_BYTES || length > MAX_SECRET_BYTES) throw new OtpError("INVALID_SECRET");
  return secret;
}

export function parseAlgorithm(raw: string | undefined): OtpAlgorithm {
  if (raw === undefined) return "SHA1";
  const a = raw.trim().toUpperCase().replace("-", "");
  if (a === "SHA1" || a === "SHA256" || a === "SHA512") return a;
  throw new OtpError("INVALID_ALGORITHM");
}

function parseUint(
  raw: string,
  code: "INVALID_DIGITS" | "INVALID_PERIOD" | "INVALID_COUNTER",
): number {
  if (!UINT_RE.test(raw)) throw new OtpError(code);
  const n = Number(raw);
  if (!Number.isSafeInteger(n)) throw new OtpError(code);
  return n;
}

export function validateDigits(type: OtpType, digits: number): number {
  if (type === "steam") return STEAM_DIGITS;
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) throw new OtpError("INVALID_DIGITS");
  return digits;
}

export function validatePeriod(period: number): number {
  if (!Number.isInteger(period) || period < 1 || period > MAX_PERIOD)
    throw new OtpError("INVALID_PERIOD");
  return period;
}

export function validateCounter(counter: number): number {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new OtpError("INVALID_COUNTER");
  return counter;
}

function steamParams(account: string, issuer: string, secret: string): OtpParams {
  return {
    type: "steam",
    issuer,
    account,
    secret,
    algorithm: "SHA1",
    digits: STEAM_DIGITS,
    period: DEFAULT_PERIOD,
    counter: 0,
  };
}

/** Splits "Issuer:account" (first colon). */
export function splitLabel(label: string): { issuer: string; account: string } {
  const colon = label.indexOf(":");
  if (colon === -1) return { issuer: "", account: label.trim() };
  return { issuer: label.slice(0, colon).trim(), account: label.slice(colon + 1).trim() };
}

/**
 * Parses `otpauth://totp|hotp|steam/…` (Google Key URI format) and `steam://SECRET`.
 * Steam is detected by type `steam`, `encoder=steam`, or issuer "Steam" (case-insensitive).
 */
export function parseOtpAuthUri(input: string): OtpParams {
  const uri = input.trim();

  const steamMatch = STEAM_RE.exec(uri);
  if (steamMatch?.[1] !== undefined) {
    return steamParams("", "Steam", parseSecret(decode(steamMatch[1])));
  }

  const m = OTPAUTH_RE.exec(uri);
  if (m === null) throw new OtpError("INVALID_URI");
  const rawType = (m[1] ?? "").toLowerCase();
  const label = splitLabel(decode(m[2] ?? ""));
  const query = parseQuery(m[3] ?? "");

  if (rawType !== "totp" && rawType !== "hotp" && rawType !== "steam") {
    throw new OtpError("UNSUPPORTED_TYPE");
  }
  const issuerParam = query.get("issuer")?.trim() ?? "";
  const issuer = issuerParam !== "" ? issuerParam : label.issuer;
  const secret = parseSecret(query.get("secret"));

  const isSteam =
    rawType === "steam" ||
    query.get("encoder")?.toLowerCase() === "steam" ||
    issuer.toLowerCase() === "steam";
  if (isSteam) return steamParams(label.account, issuer, secret);

  const type: OtpType = rawType;
  const algorithm = parseAlgorithm(query.get("algorithm"));
  const digitsRaw = query.get("digits");
  const digits = validateDigits(
    type,
    digitsRaw === undefined ? DEFAULT_DIGITS : parseUint(digitsRaw, "INVALID_DIGITS"),
  );

  let period = DEFAULT_PERIOD;
  let counter = 0;
  if (type === "totp") {
    const periodRaw = query.get("period");
    if (periodRaw !== undefined) period = validatePeriod(parseUint(periodRaw, "INVALID_PERIOD"));
  } else {
    const counterRaw = query.get("counter");
    if (counterRaw === undefined) throw new OtpError("INVALID_COUNTER");
    counter = validateCounter(parseUint(counterRaw, "INVALID_COUNTER"));
  }

  return { type, issuer, account: label.account, secret, algorithm, digits, period, counter };
}

/** Builds an otpauth:// URI that this parser (and Google Authenticator for totp/hotp) reads back. */
export function toOtpAuthUri(p: OtpParams): string {
  const enc = encodeURIComponent;
  const label = p.issuer === "" ? enc(p.account) : `${enc(p.issuer)}:${enc(p.account)}`;
  const q = [`secret=${p.secret}`];
  if (p.issuer !== "") q.push(`issuer=${enc(p.issuer)}`);
  if (p.type === "steam") {
    q.push("encoder=steam", `digits=${STEAM_DIGITS}`, `period=${DEFAULT_PERIOD}`);
    return `otpauth://totp/${label}?${q.join("&")}`;
  }
  q.push(`algorithm=${p.algorithm}`, `digits=${p.digits}`);
  q.push(p.type === "totp" ? `period=${p.period}` : `counter=${p.counter}`);
  return `otpauth://${p.type}/${label}?${q.join("&")}`;
}
