import { canonicalJson } from "./canonical.js";
import { ctx, type ItemKind } from "./context.js";
import { type Bytes, fromUtf8, utf8, wipe } from "./encoding.js";
import { open, seal, sealWithNonce } from "./envelope.js";
import { CryptoError } from "./errors.js";

export const PAD_BUCKET = 256;
/** 8192 base64url chars = 6144 bytes − 29 bytes overhead, rounded down to a bucket. */
export const MAX_PADDED_BYTES = 5888;
export const MAX_BLOB_CHARS = 8192;

/** u32be(len) ‖ data ‖ 0x00… up to the next multiple of 256 (spec/crypto.md §6.2). */
export function padPlaintext(data: Uint8Array, maxPadded: number = MAX_PADDED_BYTES): Bytes {
  const total = Math.ceil((4 + data.length) / PAD_BUCKET) * PAD_BUCKET;
  if (total > maxPadded) throw new CryptoError("ITEM_TOO_LARGE");
  const out = new Uint8Array(total);
  new DataView(out.buffer).setUint32(0, data.length);
  out.set(data, 4);
  return out;
}

export function unpadPlaintext(padded: Uint8Array): Bytes {
  if (padded.length < 4 || padded.length % PAD_BUCKET !== 0)
    throw new CryptoError("DECRYPT_FAILED");
  const len = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0);
  if (4 + len > padded.length) throw new CryptoError("DECRYPT_FAILED");
  let nonZero = 0;
  for (let i = 4 + len; i < padded.length; i++) nonZero |= padded[i] ?? 0;
  if (nonZero !== 0) throw new CryptoError("DECRYPT_FAILED");
  return padded.slice(4, 4 + len);
}

export interface ItemRef {
  userId: string;
  itemId: string;
  kind: ItemKind;
}

export function encodeItemPlaintext(value: object): Bytes {
  return padPlaintext(utf8(canonicalJson(value)));
}

/** Encrypts an item object with the vault key: JCS → pad → Envelope. */
export async function encryptItem(
  vaultKey: CryptoKey,
  ref: ItemRef,
  value: object,
): Promise<string> {
  const context = ctx.item(ref.userId, ref.itemId, ref.kind);
  const padded = encodeItemPlaintext(value);
  try {
    return await seal(vaultKey, padded, context);
  } finally {
    wipe(padded);
  }
}

/** @internal fixed-nonce variant for test vectors; exported only via `@zk2fa/crypto/testing`. */
export async function encryptItemWithNonce(
  vaultKey: CryptoKey,
  ref: ItemRef,
  value: object,
  nonce: Uint8Array,
): Promise<string> {
  return sealWithNonce(
    vaultKey,
    encodeItemPlaintext(value),
    ctx.item(ref.userId, ref.itemId, ref.kind),
    nonce,
  );
}

/** Decrypts an item to its JSON value (not yet schema-validated). */
export async function decryptItem(
  vaultKey: CryptoKey,
  ref: ItemRef,
  envelope: string,
): Promise<unknown> {
  if (envelope.length > MAX_BLOB_CHARS) throw new CryptoError("INVALID_ENVELOPE");
  const padded = await open(vaultKey, envelope, ctx.item(ref.userId, ref.itemId, ref.kind));
  const json = unpadPlaintext(padded);
  wipe(padded);
  try {
    return JSON.parse(fromUtf8(json)) as unknown;
  } catch (e: unknown) {
    if (e instanceof SyntaxError || e instanceof CryptoError) throw new CryptoError("INVALID_ITEM");
    throw e;
  } finally {
    wipe(json);
  }
}
