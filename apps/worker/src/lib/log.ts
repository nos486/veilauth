/**
 * The only logging entry point. Accepts a fixed event name and an allowlist of non-sensitive fields;
 * secrets, tokens, ciphertext, e-mails and IPs must never be passed here (build spec rule 7).
 */
export interface LogFields {
  name?: string;
  path?: string;
  /** names (never values) of required secrets that are not set */
  missing?: string[];
  /** a fixed setup hint derived from the error, never the error message itself */
  hint?: "D1_SCHEMA_MISSING";
}

export function logError(event: string, fields: LogFields): void {
  // eslint-disable-next-line no-console -- structured, allowlisted log line for Workers Logs
  console.error(JSON.stringify({ level: "error", event, ...fields }));
}
