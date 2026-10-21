import type { ApiErrorCode } from "@zk2fa/shared";
import type { ContentfulStatusCode } from "hono/utils/http-status";

const STATUS: Record<ApiErrorCode, ContentfulStatusCode> = {
  BAD_REQUEST: 400,
  PAYLOAD_TOO_LARGE: 413,
  UNAUTHORIZED: 401,
  INVALID_CREDENTIALS: 401,
  TOKEN_EXPIRED: 401,
  SESSION_REVOKED: 401,
  REFRESH_REUSED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  EMAIL_TAKEN: 409,
  ID_TAKEN: 409,
  KDF_PARAMS_REJECTED: 400,
  RATE_LIMITED: 429,
  ACCOUNT_LOCKED: 429,
  TURNSTILE_REQUIRED: 401,
  TURNSTILE_FAILED: 401,
  VAULT_LIMIT: 409,
  SYNC_RETRY: 409,
  INTERNAL: 500,
};

const MESSAGES: Record<ApiErrorCode, string> = {
  BAD_REQUEST: "The request is invalid.",
  PAYLOAD_TOO_LARGE: "The request body is too large.",
  UNAUTHORIZED: "Authentication is required.",
  INVALID_CREDENTIALS: "E-mail or password is incorrect.",
  TOKEN_EXPIRED: "The access token has expired.",
  SESSION_REVOKED: "This session is no longer valid.",
  REFRESH_REUSED: "The refresh token was already used; the session has been revoked.",
  FORBIDDEN: "Not allowed.",
  NOT_FOUND: "Not found.",
  EMAIL_TAKEN: "An account with this e-mail already exists.",
  ID_TAKEN: "This id is already in use.",
  KDF_PARAMS_REJECTED: "Key-derivation parameters are not acceptable.",
  RATE_LIMITED: "Too many requests. Try again later.",
  ACCOUNT_LOCKED: "Too many failed attempts. Try again later.",
  TURNSTILE_REQUIRED: "Please complete the human check.",
  TURNSTILE_FAILED: "The human check failed.",
  VAULT_LIMIT: "The vault item limit has been reached.",
  SYNC_RETRY: "The vault changed concurrently; sync again.",
  INTERNAL: "Internal error.",
};

/** API error with a stable code. `detail` is a fixed developer hint and never contains request data. */
export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status: ContentfulStatusCode;
  readonly retryAfterSeconds: number | undefined;

  constructor(code: ApiErrorCode, options: { detail?: string; retryAfterSeconds?: number } = {}) {
    super(options.detail ?? MESSAGES[code]);
    this.name = "ApiError";
    this.code = code;
    this.status = STATUS[code];
    this.retryAfterSeconds = options.retryAfterSeconds;
  }
}
