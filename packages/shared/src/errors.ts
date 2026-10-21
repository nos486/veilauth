/** Stable API error codes. Clients switch on `code`; `message` is for humans and never echoes input. */
export const API_ERROR_CODES = [
  "BAD_REQUEST",
  "PAYLOAD_TOO_LARGE",
  "UNAUTHORIZED",
  "INVALID_CREDENTIALS",
  "TOKEN_EXPIRED",
  "SESSION_REVOKED",
  "REFRESH_REUSED",
  "FORBIDDEN",
  "NOT_FOUND",
  "EMAIL_TAKEN",
  "ID_TAKEN",
  "KDF_PARAMS_REJECTED",
  "RATE_LIMITED",
  "ACCOUNT_LOCKED",
  "TURNSTILE_REQUIRED",
  "TURNSTILE_FAILED",
  "VAULT_LIMIT",
  "SYNC_RETRY",
  "INTERNAL",
] as const;

export type ApiErrorCode = (typeof API_ERROR_CODES)[number];
