export const OTP_ALGORITHMS = ["SHA1", "SHA256", "SHA512"] as const;
export type OtpAlgorithm = (typeof OTP_ALGORITHMS)[number];

export const OTP_TYPES = ["totp", "hotp", "steam"] as const;
export type OtpType = (typeof OTP_TYPES)[number];

/** Token parameters as stored in the vault (spec/crypto.md §6.3). `secret` is base32, upper-case, unpadded. */
export interface OtpParams {
  type: OtpType;
  issuer: string;
  account: string;
  secret: string;
  algorithm: OtpAlgorithm;
  digits: number;
  period: number;
  counter: number;
}

export const DEFAULT_PERIOD = 30;
export const DEFAULT_DIGITS = 6;
export const STEAM_DIGITS = 5;
export const MAX_PERIOD = 86_400;
export const MIN_SECRET_BYTES = 1;
export const MAX_SECRET_BYTES = 128;
