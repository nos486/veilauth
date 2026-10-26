import { canonicalJson } from "./canonical.js";
import { ctx } from "./context.js";
import {
  type Bytes,
  fromBase64Url,
  fromUtf8,
  randomBytes,
  toBase64Url,
  utf8,
  wipe,
} from "./encoding.js";
import { NONCE_BYTES, open, sealWithNonce } from "./envelope.js";
import { CryptoError } from "./errors.js";
import { padPlaintext, unpadPlaintext } from "./item.js";
import { deriveMasterKey, hkdfToAesKey } from "./kdf.js";
import {
  DEFAULT_KDF_PARAMS,
  KDF_ALG,
  KDF_SALT_BYTES,
  type KdfParams,
  validateKdfParams,
} from "./params.js";
import { type TokenItem, validateTokenItem } from "./token.js";

export const BACKUP_FORMAT = "veilauth-backup";
export const BACKUP_VERSION = 1;
export const INFO_BACKUP = "zk2fa/v1/backup";
/** Same as the server's vault limit. */
export const MAX_BACKUP_TOKENS = 1000;
/** 1000 items of at most 5888 padded bytes each, with room to spare. */
export const MAX_BACKUP_PADDED_BYTES = 8 * 1024 * 1024;
const MAX_BACKUP_FILE_CHARS = 12 * 1024 * 1024;

/** What a backup file holds once opened (spec/crypto.md §9). */
export interface BackupContents {
  /** unix ms */
  exportedAt: number;
  tokens: TokenItem[];
}

async function backupKey(
  password: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<CryptoKey> {
  const masterKey = await deriveMasterKey(password, salt, params);
  try {
    return await hkdfToAesKey(masterKey, INFO_BACKUP);
  } finally {
    wipe(masterKey);
  }
}

function checkContents(value: unknown): BackupContents {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new CryptoError("INVALID_BACKUP");
  const { exportedAt, tokens } = value as Record<string, unknown>;
  if (typeof exportedAt !== "number" || !Number.isSafeInteger(exportedAt) || exportedAt < 0)
    throw new CryptoError("INVALID_BACKUP");
  if (!Array.isArray(tokens) || tokens.length > MAX_BACKUP_TOKENS)
    throw new CryptoError("INVALID_BACKUP");
  return { exportedAt, tokens: tokens.map(validateTokenItem) };
}

/** @internal fixed salt and nonce for test vectors; exported only via `@zk2fa/crypto/testing`. */
export async function createBackupWith(
  password: string,
  contents: BackupContents,
  salt: Uint8Array,
  nonce: Uint8Array,
): Promise<string> {
  const checked = checkContents(contents);
  const params = { ...DEFAULT_KDF_PARAMS };
  const key = await backupKey(password, salt, params);
  const padded = padPlaintext(utf8(canonicalJson(checked)), MAX_BACKUP_PADDED_BYTES);
  try {
    const data = await sealWithNonce(key, padded, ctx.backup(salt), nonce);
    return canonicalJson({
      format: BACKUP_FORMAT,
      version: BACKUP_VERSION,
      kdf: { alg: KDF_ALG, params, salt: toBase64Url(salt) },
      data,
    });
  } finally {
    wipe(padded);
  }
}

/** Encrypts the tokens into a password-protected backup file (JSON text). */
export function createBackup(password: string, contents: BackupContents): Promise<string> {
  return createBackupWith(
    password,
    contents,
    randomBytes(KDF_SALT_BYTES),
    randomBytes(NONCE_BYTES),
  );
}

/**
 * Opens a backup file. A malformed file is INVALID_BACKUP; a wrong password (or a tampered file)
 * is DECRYPT_FAILED. KDF parameters are checked before Argon2id runs, as for prelogin.
 */
export async function openBackup(password: string, file: string): Promise<BackupContents> {
  if (file.length > MAX_BACKUP_FILE_CHARS) throw new CryptoError("INVALID_BACKUP");
  let parsed: unknown;
  try {
    parsed = JSON.parse(file);
  } catch (e: unknown) {
    if (e instanceof SyntaxError) throw new CryptoError("INVALID_BACKUP");
    throw e;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
    throw new CryptoError("INVALID_BACKUP");
  const { format, version, kdf, data } = parsed as Record<string, unknown>;
  if (format !== BACKUP_FORMAT || version !== BACKUP_VERSION || typeof data !== "string")
    throw new CryptoError("INVALID_BACKUP");
  if (typeof kdf !== "object" || kdf === null) throw new CryptoError("INVALID_BACKUP");
  const { alg, params, salt } = kdf as Record<string, unknown>;
  if (typeof alg !== "string" || typeof salt !== "string") throw new CryptoError("INVALID_BACKUP");
  let saltBytes: Bytes;
  try {
    saltBytes = fromBase64Url(salt);
  } catch (e: unknown) {
    if (e instanceof CryptoError) throw new CryptoError("INVALID_BACKUP");
    throw e;
  }
  const checkedParams = validateKdfParams(alg, params, saltBytes);
  const key = await backupKey(password, saltBytes, checkedParams);
  let padded: Bytes;
  try {
    padded = await open(key, data, ctx.backup(saltBytes));
  } catch (e: unknown) {
    if (e instanceof CryptoError && e.code === "INVALID_ENVELOPE")
      throw new CryptoError("INVALID_BACKUP");
    throw e;
  }
  const json = unpadPlaintext(padded);
  wipe(padded);
  let value: unknown;
  try {
    value = JSON.parse(fromUtf8(json));
  } catch (e: unknown) {
    if (e instanceof SyntaxError || e instanceof CryptoError)
      throw new CryptoError("INVALID_BACKUP");
    throw e;
  } finally {
    wipe(json);
  }
  return checkContents(value);
}
