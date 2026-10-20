import { CryptoError } from "./errors.js";

export const KDF_ALG = "argon2id" as const;

export interface KdfParams {
  /** memory in KiB */
  m: number;
  /** passes */
  t: number;
  /** lanes */
  p: number;
}

export const CURRENT_KDF_VERSION = 1;
export const KDF_PARAMS_BY_VERSION: Readonly<Record<number, Readonly<KdfParams>>> = {
  1: { m: 65_536, t: 3, p: 1 },
};
export const DEFAULT_KDF_PARAMS: Readonly<KdfParams> = { m: 65_536, t: 3, p: 1 };

export const KDF_SALT_BYTES = 16;
export const KEY_BYTES = 32;
export const PBKDF2_ITERATIONS = 100_000;
export const AUTH_SALT_BYTES = 16;

const LIMITS = { mMin: 65_536, mMax: 262_144, tMin: 3, tMax: 16 } as const;

/**
 * Validates prelogin KDF parameters before running the KDF (spec/crypto.md §3).
 * Rejects downgrades by a malicious server and absurd values that would DoS the client.
 */
export function validateKdfParams(alg: string, params: unknown, salt: Uint8Array): KdfParams {
  if (alg !== KDF_ALG) throw new CryptoError("KDF_PARAMS_REJECTED");
  if (typeof params !== "object" || params === null) throw new CryptoError("KDF_PARAMS_REJECTED");
  const { m, t, p } = params as Record<string, unknown>;
  if (
    typeof m !== "number" ||
    typeof t !== "number" ||
    typeof p !== "number" ||
    !Number.isInteger(m) ||
    !Number.isInteger(t) ||
    m < LIMITS.mMin ||
    m > LIMITS.mMax ||
    t < LIMITS.tMin ||
    t > LIMITS.tMax ||
    p !== 1
  ) {
    throw new CryptoError("KDF_PARAMS_REJECTED");
  }
  if (salt.length !== KDF_SALT_BYTES) throw new CryptoError("KDF_PARAMS_REJECTED");
  return { m, t, p };
}
