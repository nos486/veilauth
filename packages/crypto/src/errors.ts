export type CryptoErrorCode =
  | "DECRYPT_FAILED"
  | "INVALID_ENVELOPE"
  | "INVALID_CONTEXT"
  | "INVALID_ENCODING"
  | "KDF_PARAMS_REJECTED"
  | "INVALID_MNEMONIC"
  | "INVALID_ITEM"
  | "ITEM_TOO_LARGE";

/** Error with a stable code; never carries key material, plaintext or ciphertext. */
export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message?: string) {
    super(message ?? code);
    this.name = "CryptoError";
    this.code = code;
  }
}
