import { base32Encode } from "./base32.js";
import { OtpError } from "./errors.js";
import { splitLabel, validateCounter } from "./otpauth.js";
import type { OtpAlgorithm, OtpParams } from "./types.js";
import { DEFAULT_PERIOD, MAX_SECRET_BYTES } from "./types.js";

/**
 * Decoder for Google Authenticator export QR codes:
 *   otpauth-migration://offline?data=<base64 MigrationPayload protobuf>
 *
 * message MigrationPayload {
 *   repeated OtpParameters otp_parameters = 1;
 *   int32 version = 2; int32 batch_size = 3; int32 batch_index = 4; int32 batch_id = 5;
 * }
 * message OtpParameters {
 *   bytes secret = 1; string name = 2; string issuer = 3;
 *   Algorithm algorithm = 4;  // 0 unspecified(SHA1) 1 SHA1 2 SHA256 3 SHA512 4 MD5
 *   DigitCount digits = 5;    // 0 unspecified(6) 1 SIX 2 EIGHT
 *   OtpType type = 6;         // 0 unspecified(TOTP) 1 HOTP 2 TOTP
 *   int64 counter = 7;
 * }
 */

export type MigrationEntry =
  | { ok: true; value: OtpParams }
  | { ok: false; error: OtpError["code"]; issuer: string; account: string };

export interface MigrationPayload {
  version: number;
  batchSize: number;
  batchIndex: number;
  batchId: number;
  entries: MigrationEntry[];
}

const MAX_PAYLOAD_BYTES = 64 * 1024;

class Reader {
  pos = 0;
  constructor(private readonly buf: Uint8Array) {}

  get done(): boolean {
    return this.pos >= this.buf.length;
  }

  varint(): bigint {
    let result = 0n;
    for (let shift = 0n; shift < 70n; shift += 7n) {
      const b = this.buf[this.pos++];
      if (b === undefined) throw fail();
      result |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) return BigInt.asUintN(64, result);
    }
    throw fail();
  }

  bytes(): Uint8Array {
    const len = Number(this.varint());
    if (len > this.buf.length - this.pos) throw fail();
    const out = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }

  skip(wireType: number): void {
    switch (wireType) {
      case 0:
        this.varint();
        return;
      case 1:
        this.advance(8);
        return;
      case 2:
        this.bytes();
        return;
      case 5:
        this.advance(4);
        return;
      default:
        throw fail();
    }
  }

  private advance(n: number): void {
    if (n > this.buf.length - this.pos) throw fail();
    this.pos += n;
  }
}

function fail(): OtpError {
  return new OtpError("MIGRATION_DECODE_FAILED");
}

const utf8 = new TextDecoder("utf-8", { fatal: true });

function str(bytes: Uint8Array): string {
  try {
    return utf8.decode(bytes);
  } catch (e: unknown) {
    if (e instanceof TypeError) throw fail();
    throw e;
  }
}

/** int32 fields are sign-extended to 64 bits on the wire. */
function int32(v: bigint): number {
  return Number(BigInt.asIntN(32, v));
}

interface RawOtp {
  secret: Uint8Array;
  name: string;
  issuer: string;
  algorithm: number;
  digits: number;
  type: number;
  counter: bigint;
}

function readOtp(bytes: Uint8Array): RawOtp {
  const r = new Reader(bytes);
  const o: RawOtp = {
    secret: new Uint8Array(),
    name: "",
    issuer: "",
    algorithm: 0,
    digits: 0,
    type: 0,
    counter: 0n,
  };
  while (!r.done) {
    const tag = Number(r.varint());
    const field = tag >>> 3;
    const wire = tag & 7;
    if (field === 1 && wire === 2) o.secret = r.bytes();
    else if (field === 2 && wire === 2) o.name = str(r.bytes());
    else if (field === 3 && wire === 2) o.issuer = str(r.bytes());
    else if (field === 4 && wire === 0) o.algorithm = int32(r.varint());
    else if (field === 5 && wire === 0) o.digits = int32(r.varint());
    else if (field === 6 && wire === 0) o.type = int32(r.varint());
    else if (field === 7 && wire === 0) o.counter = BigInt.asIntN(64, r.varint());
    else r.skip(wire);
  }
  return o;
}

const ALGORITHMS: Record<number, OtpAlgorithm | undefined> = {
  0: "SHA1",
  1: "SHA1",
  2: "SHA256",
  3: "SHA512",
};

function toEntry(o: RawOtp): MigrationEntry {
  const issuer = o.issuer.trim();
  let account = o.name.trim();
  if (issuer === "") {
    const split = splitLabel(o.name);
    if (split.issuer !== "") return convert(o, split.issuer, split.account);
  } else if (account.startsWith(`${issuer}:`)) {
    account = account.slice(issuer.length + 1).trim();
  }
  return convert(o, issuer, account);
}

function convert(o: RawOtp, issuer: string, account: string): MigrationEntry {
  const bad = (error: OtpError["code"]): MigrationEntry => ({ ok: false, error, issuer, account });
  const algorithm = ALGORITHMS[o.algorithm];
  if (algorithm === undefined) return bad("INVALID_ALGORITHM");
  const digits = o.digits === 0 || o.digits === 1 ? 6 : o.digits === 2 ? 8 : undefined;
  if (digits === undefined) return bad("INVALID_DIGITS");
  if (o.secret.length === 0 || o.secret.length > MAX_SECRET_BYTES) return bad("INVALID_SECRET");
  const type = o.type === 1 ? "hotp" : o.type === 0 || o.type === 2 ? "totp" : undefined;
  if (type === undefined) return bad("UNSUPPORTED_TYPE");
  let counter = 0;
  if (type === "hotp") {
    if (o.counter < 0n || o.counter > BigInt(Number.MAX_SAFE_INTEGER))
      return bad("INVALID_COUNTER");
    counter = validateCounter(Number(o.counter));
  }
  return {
    ok: true,
    value: {
      type,
      issuer,
      account,
      secret: base32Encode(o.secret),
      algorithm,
      digits,
      period: DEFAULT_PERIOD,
      counter,
    },
  };
}

function base64ToBytes(b64: string): Uint8Array {
  // Accept standard and url-safe alphabets; a literal '+' may have been turned into a space.
  const s = b64.replace(/ /g, "+").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/]*$/.test(s) || s.length % 4 === 1) throw fail();
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Decodes one otpauth-migration:// URI. Per-entry problems are reported in `entries`, not thrown. */
export function decodeMigrationUri(input: string): MigrationPayload {
  const m = /^otpauth-migration:\/\/offline\/?\?(.*)$/is.exec(input.trim());
  if (m?.[1] === undefined) throw new OtpError("INVALID_URI");
  let data: string | undefined;
  for (const part of m[1].split("&")) {
    if (part.startsWith("data=")) {
      try {
        data = decodeURIComponent(part.slice(5));
      } catch (e: unknown) {
        if (e instanceof URIError) throw new OtpError("INVALID_URI");
        throw e;
      }
      break;
    }
  }
  if (data === undefined || data === "") throw new OtpError("INVALID_URI");
  if (data.length > (MAX_PAYLOAD_BYTES * 4) / 3 + 4) throw fail();
  return decodeMigrationPayload(base64ToBytes(data));
}

export function decodeMigrationPayload(bytes: Uint8Array): MigrationPayload {
  const r = new Reader(bytes);
  const payload: MigrationPayload = {
    version: 0,
    batchSize: 1,
    batchIndex: 0,
    batchId: 0,
    entries: [],
  };
  while (!r.done) {
    const tag = Number(r.varint());
    const field = tag >>> 3;
    const wire = tag & 7;
    if (field === 1 && wire === 2) payload.entries.push(toEntry(readOtp(r.bytes())));
    else if (field === 2 && wire === 0) payload.version = int32(r.varint());
    else if (field === 3 && wire === 0) payload.batchSize = int32(r.varint());
    else if (field === 4 && wire === 0) payload.batchIndex = int32(r.varint());
    else if (field === 5 && wire === 0) payload.batchId = int32(r.varint());
    else r.skip(wire);
  }
  if (payload.batchSize < 1 || payload.batchIndex < 0 || payload.batchIndex >= payload.batchSize)
    throw fail();
  return payload;
}

export type BatchAddResult =
  | { status: "incomplete"; received: number; total: number }
  | { status: "complete"; entries: MigrationEntry[] }
  | { status: "duplicate"; received: number; total: number };

/** Collects the QR codes of a multi-QR Google Authenticator export (same batchId) in any order. */
export class MigrationBatch {
  private batchId: number | undefined;
  private total = 0;
  private readonly parts = new Map<number, MigrationEntry[]>();

  add(payload: MigrationPayload): BatchAddResult {
    if (this.batchId === undefined) {
      this.batchId = payload.batchId;
      this.total = payload.batchSize;
    } else if (payload.batchId !== this.batchId || payload.batchSize !== this.total) {
      throw new OtpError("MIGRATION_DECODE_FAILED", "QR code belongs to a different export");
    }
    if (this.parts.has(payload.batchIndex)) {
      return { status: "duplicate", received: this.parts.size, total: this.total };
    }
    this.parts.set(payload.batchIndex, payload.entries);
    if (this.parts.size < this.total) {
      return { status: "incomplete", received: this.parts.size, total: this.total };
    }
    const entries: MigrationEntry[] = [];
    for (let i = 0; i < this.total; i++) entries.push(...(this.parts.get(i) ?? []));
    return { status: "complete", entries };
  }
}
