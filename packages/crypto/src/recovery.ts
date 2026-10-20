import { entropyToMnemonic, mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { type Bytes, copyBytes, randomBytes } from "./encoding.js";
import { CryptoError } from "./errors.js";
import { hkdfSha256, hkdfToAesKey, INFO_RECOVERY_AUTH, INFO_RECOVERY_KEK } from "./kdf.js";
import { KEY_BYTES } from "./params.js";

export const RECOVERY_WORD_COUNT = 24;

export function generateRecoveryKey(): Bytes {
  return randomBytes(KEY_BYTES);
}

/** 32 bytes → 24 BIP39 English words (encoding only; the BIP39 seed function is not used). */
export function recoveryKeyToMnemonic(recoveryKey: Uint8Array): string {
  if (recoveryKey.length !== KEY_BYTES) throw new CryptoError("INVALID_MNEMONIC");
  return entropyToMnemonic(recoveryKey, wordlist);
}

export function normalizeMnemonic(input: string): string {
  return input.normalize("NFKD").trim().toLowerCase().split(/\s+/).join(" ");
}

/** 24 words → 32 bytes; verifies the checksum. */
export function mnemonicToRecoveryKey(input: string): Bytes {
  const mnemonic = normalizeMnemonic(input);
  if (mnemonic.split(" ").length !== RECOVERY_WORD_COUNT) throw new CryptoError("INVALID_MNEMONIC");
  try {
    return copyBytes(mnemonicToEntropy(mnemonic, wordlist));
  } catch (e: unknown) {
    if (e instanceof Error) throw new CryptoError("INVALID_MNEMONIC");
    throw e;
  }
}

export interface RecoveryKeys {
  /** sent to the server on recovery; hashed there like authKey */
  recoveryAuth: Bytes;
  /** non-extractable; wraps the vault key a second time */
  recoveryKek: CryptoKey;
}

export async function deriveRecoveryKeys(recoveryKey: Uint8Array): Promise<RecoveryKeys> {
  const [recoveryAuth, recoveryKek] = await Promise.all([
    hkdfSha256(recoveryKey, INFO_RECOVERY_AUTH),
    hkdfToAesKey(recoveryKey, INFO_RECOVERY_KEK),
  ]);
  return { recoveryAuth, recoveryKek };
}
