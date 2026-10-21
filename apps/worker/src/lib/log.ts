/**
 * The only logging entry point. Accepts a fixed event name and an allowlist of non-sensitive fields;
 * secrets, tokens, ciphertext, e-mails and IPs must never be passed here (build spec rule 7).
 */
export function logError(event: string, fields: { name?: string; path?: string }): void {
  // eslint-disable-next-line no-console -- structured, allowlisted log line for Workers Logs
  console.error(JSON.stringify({ level: "error", event, ...fields }));
}
