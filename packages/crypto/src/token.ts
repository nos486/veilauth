import { CryptoError } from "./errors.js";

export interface TokenItem {
  type: "totp" | "hotp" | "steam";
  issuer: string;
  account: string;
  secret: string;
  algorithm: "SHA1" | "SHA256" | "SHA512";
  digits: number;
  period: number;
  counter: number;
  iconId: string | null;
  folderId: string | null;
  tags: string[];
  notes: string;
  favorite: boolean;
  createdAt: number;
  trashedAt: number | null;
  /** unknown keys are preserved for forward compatibility (spec/crypto.md §6.3) */
  [extra: string]: unknown;
}

export interface FolderItem {
  name: string;
  createdAt: number;
  [extra: string]: unknown;
}

const BASE32 = /^[A-Z2-7]+$/;

function fail(field: string): never {
  throw new CryptoError("INVALID_ITEM", `invalid field: ${field}`);
}

function str(v: unknown, field: string, max: number): string {
  if (typeof v !== "string" || v.length > max) fail(field);
  return v;
}

function int(v: unknown, field: string, min: number, max: number): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) fail(field);
  return v;
}

function nullableStr(v: unknown, field: string, max: number): string | null {
  return v === null ? null : str(v, field, max);
}

function obj(v: unknown): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) fail("<root>");
  return v as Record<string, unknown>;
}

/** Validates a decrypted token plaintext against spec/crypto.md §6.3. */
export function validateTokenItem(value: unknown): TokenItem {
  const o = obj(value);
  const type = o.type;
  if (type !== "totp" && type !== "hotp" && type !== "steam") fail("type");
  const algorithm = o.algorithm;
  if (algorithm !== "SHA1" && algorithm !== "SHA256" && algorithm !== "SHA512") fail("algorithm");
  if (type === "steam" && algorithm !== "SHA1") fail("algorithm");
  const secret = str(o.secret, "secret", 205);
  const secretBytes = Math.floor((secret.length * 5) / 8);
  if (!BASE32.test(secret) || secretBytes < 1 || secretBytes > 128) fail("secret");
  const digits = type === "steam" ? int(o.digits, "digits", 5, 5) : int(o.digits, "digits", 6, 8);
  const tags = o.tags;
  if (!Array.isArray(tags) || tags.length > 32) fail("tags");
  const trashedAt = o.trashedAt;
  return {
    ...o,
    type,
    issuer: str(o.issuer, "issuer", 256),
    account: str(o.account, "account", 256),
    secret,
    algorithm,
    digits,
    period: int(o.period, "period", 1, 86_400),
    counter: int(o.counter, "counter", 0, Number.MAX_SAFE_INTEGER),
    iconId: nullableStr(o.iconId, "iconId", 128),
    folderId: nullableStr(o.folderId, "folderId", 36),
    tags: tags.map((t) => str(t, "tags", 64)),
    notes: str(o.notes, "notes", 2048),
    favorite: typeof o.favorite === "boolean" ? o.favorite : fail("favorite"),
    createdAt: int(o.createdAt, "createdAt", 0, Number.MAX_SAFE_INTEGER),
    trashedAt: trashedAt === null ? null : int(trashedAt, "trashedAt", 0, Number.MAX_SAFE_INTEGER),
  };
}

export function validateFolderItem(value: unknown): FolderItem {
  const o = obj(value);
  return {
    ...o,
    name: str(o.name, "name", 128),
    createdAt: int(o.createdAt, "createdAt", 0, Number.MAX_SAFE_INTEGER),
  };
}
