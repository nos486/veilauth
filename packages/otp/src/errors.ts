export type OtpErrorCode =
  | "INVALID_URI"
  | "UNSUPPORTED_TYPE"
  | "MISSING_SECRET"
  | "INVALID_SECRET"
  | "INVALID_ALGORITHM"
  | "INVALID_DIGITS"
  | "INVALID_PERIOD"
  | "INVALID_COUNTER"
  | "INVALID_TIME"
  | "MIGRATION_DECODE_FAILED";

/** Error with a stable code. Messages never echo the input (it may contain a secret). */
export class OtpError extends Error {
  readonly code: OtpErrorCode;

  constructor(code: OtpErrorCode, message?: string) {
    super(message ?? code);
    this.name = "OtpError";
    this.code = code;
  }
}
