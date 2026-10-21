import { CryptoError } from "@zk2fa/crypto";
import { OtpError } from "@zk2fa/otp";
import { ApiError } from "../api/client";
import { UserError } from "../app/controller";
import { CryptoWorkerError } from "../crypto/client";
import { hasString, t } from "../i18n";

/** Maps any error to a user-facing sentence. Unknown errors are reported, never swallowed. */
export function errorMessage(e: unknown): string {
  let key: string | null = null;
  if (e instanceof ApiError) key = `error.${e.code}`;
  else if (e instanceof CryptoWorkerError || e instanceof CryptoError || e instanceof UserError)
    key = `error.${e.code}`;
  else if (e instanceof OtpError) key = `otp.${e.code}`;
  if (key !== null && hasString(key)) return t(key);
  reportError(e);
  return t("error.generic");
}
