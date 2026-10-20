import { type Bytes, copyBytes, randomBytes, wipe } from "./encoding.js";
import { gcmAad, parseEnvelope, seal, TAG_BYTES } from "./envelope.js";
import { CryptoError } from "./errors.js";
import { ctx } from "./context.js";
import { KEY_BYTES } from "./params.js";

export type KeyUsage = "encrypt" | "decrypt" | "wrapKey" | "unwrapKey";
const DATA_USAGES: KeyUsage[] = ["encrypt", "decrypt"];

/** Imports raw AES-256 key bytes. Non-extractable unless explicitly requested. */
export async function importAesKey(
  raw: Uint8Array,
  options: { extractable?: boolean; usages?: KeyUsage[] } = {},
): Promise<CryptoKey> {
  if (raw.length !== KEY_BYTES)
    throw new CryptoError("INVALID_ENCODING", "AES key must be 32 bytes");
  return crypto.subtle.importKey(
    "raw",
    copyBytes(raw),
    { name: "AES-GCM" },
    options.extractable ?? false,
    options.usages ?? DATA_USAGES,
  );
}

export function generateVaultKeyBytes(): Bytes {
  return randomBytes(KEY_BYTES);
}

async function rawOf(key: CryptoKey | Uint8Array): Promise<Bytes> {
  if (key instanceof Uint8Array) return copyBytes(key);
  if (!key.extractable)
    throw new CryptoError("INVALID_CONTEXT", "vault key must be extractable to re-wrap");
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

async function wrap(
  kek: CryptoKey,
  vaultKey: CryptoKey | Uint8Array,
  context: string,
): Promise<string> {
  const raw = await rawOf(vaultKey);
  try {
    if (raw.length !== KEY_BYTES)
      throw new CryptoError("INVALID_ENCODING", "vault key must be 32 bytes");
    return await seal(kek, raw, context);
  } finally {
    wipe(raw);
  }
}

/** Uses WebCrypto unwrapKey so the raw vault key never enters JS memory. */
async function unwrap(
  kek: CryptoKey,
  envelope: string,
  context: string,
  extractable: boolean,
): Promise<CryptoKey> {
  const { version, nonce, body } = parseEnvelope(envelope);
  if (body.length !== KEY_BYTES + TAG_BYTES) throw new CryptoError("DECRYPT_FAILED");
  try {
    return await crypto.subtle.unwrapKey(
      "raw",
      body,
      kek,
      { name: "AES-GCM", iv: nonce, additionalData: gcmAad(version, context), tagLength: 128 },
      { name: "AES-GCM" },
      extractable,
      DATA_USAGES,
    );
  } catch (e: unknown) {
    if (e instanceof DOMException && (e.name === "OperationError" || e.name === "DataError")) {
      throw new CryptoError("DECRYPT_FAILED");
    }
    throw e;
  }
}

/** wrappedVaultKey = Envelope(kek, vaultKey, "zk2fa/v1/vk|" + userId) */
export function wrapVaultKey(
  kek: CryptoKey,
  vaultKey: CryptoKey | Uint8Array,
  userId: string,
): Promise<string> {
  return wrap(kek, vaultKey, ctx.vaultKey(userId));
}

/**
 * Unwraps the vault key into a CryptoKey. Non-extractable by default; pass `extractable: true`
 * only for the short-lived key used to re-wrap during password change / recovery.
 */
export function unwrapVaultKey(
  kek: CryptoKey,
  wrapped: string,
  userId: string,
  options: { extractable?: boolean } = {},
): Promise<CryptoKey> {
  return unwrap(kek, wrapped, ctx.vaultKey(userId), options.extractable ?? false);
}

/** recoveryWrappedVaultKey = Envelope(recoveryKek, vaultKey, "zk2fa/v1/rvk|" + userId) */
export function wrapVaultKeyForRecovery(
  recoveryKek: CryptoKey,
  vaultKey: CryptoKey | Uint8Array,
  userId: string,
): Promise<string> {
  return wrap(recoveryKek, vaultKey, ctx.recoveryVaultKey(userId));
}

export function unwrapVaultKeyWithRecovery(
  recoveryKek: CryptoKey,
  wrapped: string,
  userId: string,
  options: { extractable?: boolean } = {},
): Promise<CryptoKey> {
  return unwrap(recoveryKek, wrapped, ctx.recoveryVaultKey(userId), options.extractable ?? false);
}
