import { CryptoError, CURRENT_KDF_VERSION, validateKdfParams } from "@zk2fa/crypto/server";
import type { Kdf } from "@zk2fa/shared";
import type { UserRow } from "../db/schema.js";
import { fromBase64Url, toBase64Url } from "./encoding.js";
import { ApiError } from "./errors.js";

/** Canonical (JCS) storage form of KDF params. */
export function kdfParamsJson(p: { m: number; t: number; p: number }): string {
  return `{"m":${p.m},"p":${p.p},"t":${p.t}}`;
}

/** Server enforces the same parameter floor as the clients (D-005), so weak params are never stored. */
export function acceptKdf(kdf: Kdf): {
  alg: string;
  params: string;
  salt: Uint8Array<ArrayBuffer>;
  version: number;
} {
  const salt = fromBase64Url(kdf.salt);
  if (kdf.version < 1 || kdf.version > CURRENT_KDF_VERSION)
    throw new ApiError("KDF_PARAMS_REJECTED");
  try {
    const params = validateKdfParams(kdf.alg, kdf.params, salt);
    return { alg: kdf.alg, params: kdfParamsJson(params), salt, version: kdf.version };
  } catch (e: unknown) {
    if (e instanceof CryptoError) throw new ApiError("KDF_PARAMS_REJECTED");
    throw e;
  }
}

export function kdfOf(user: Pick<UserRow, "kdfAlg" | "kdfVersion" | "kdfParams" | "kdfSalt">): Kdf {
  const params = JSON.parse(user.kdfParams) as { m: number; t: number; p: number };
  return { alg: "argon2id", version: user.kdfVersion, params, salt: toBase64Url(user.kdfSalt) };
}
