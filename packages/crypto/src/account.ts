import { type Bytes, randomBytes, wipe } from "./encoding.js";
import { deriveLoginKeys } from "./kdf.js";
import {
  importAesKey,
  generateVaultKeyBytes,
  wrapVaultKey,
  wrapVaultKeyForRecovery,
} from "./keys.js";
import {
  CURRENT_KDF_VERSION,
  DEFAULT_KDF_PARAMS,
  KDF_ALG,
  type KdfParams,
  KDF_SALT_BYTES,
} from "./params.js";
import { deriveRecoveryKeys, generateRecoveryKey, recoveryKeyToMnemonic } from "./recovery.js";

export interface NewAccountKeys {
  kdf: { alg: typeof KDF_ALG; version: number; params: KdfParams; salt: Bytes };
  authKey: Bytes;
  wrappedVaultKey: string;
  recoveryAuth: Bytes;
  recoveryWrappedVaultKey: string;
  /** shown once to the user, then dropped */
  recoveryMnemonic: string;
  /** non-extractable, ready to use */
  vaultKey: CryptoKey;
}

/** Everything the client creates at signup (spec/crypto.md §4). */
export async function createAccountKeys(password: string, userId: string): Promise<NewAccountKeys> {
  const salt = randomBytes(KDF_SALT_BYTES);
  const params = { ...DEFAULT_KDF_PARAMS };
  const { authKey, kek } = await deriveLoginKeys(password, salt, params);
  const vaultKeyRaw = generateVaultKeyBytes();
  const recoveryKey = generateRecoveryKey();
  try {
    const { recoveryAuth, recoveryKek } = await deriveRecoveryKeys(recoveryKey);
    const [wrappedVaultKey, recoveryWrappedVaultKey, vaultKey] = await Promise.all([
      wrapVaultKey(kek, vaultKeyRaw, userId),
      wrapVaultKeyForRecovery(recoveryKek, vaultKeyRaw, userId),
      importAesKey(vaultKeyRaw),
    ]);
    return {
      kdf: { alg: KDF_ALG, version: CURRENT_KDF_VERSION, params, salt },
      authKey,
      wrappedVaultKey,
      recoveryAuth,
      recoveryWrappedVaultKey,
      recoveryMnemonic: recoveryKeyToMnemonic(recoveryKey),
      vaultKey,
    };
  } finally {
    wipe(vaultKeyRaw, recoveryKey);
  }
}
