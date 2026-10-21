import { canonicalJson, type TokenItem } from "@zk2fa/crypto";

/** Appended to the account name of the copy kept when two devices edited one token (build spec §5.3). */
export const CONFLICT_SUFFIX = " (conflicted copy)";

export type TokenResolution =
  /** both sides are the same: drop the local change */
  | { action: "same" }
  /** HOTP on both sides: keep the local edit with the higher counter, on top of the server copy */
  | { action: "merge"; value: TokenItem }
  /** keep the server copy as is and save the local version as a new token */
  | { action: "copy"; value: TokenItem };

/** Decides how to reconcile a locally edited token with a different server version. Never drops a token. */
export function resolveTokenConflict(local: TokenItem, server: TokenItem): TokenResolution {
  if (canonicalJson(local) === canonicalJson(server)) return { action: "same" };
  if (local.type === "hotp" && server.type === "hotp" && local.secret === server.secret) {
    return {
      action: "merge",
      value: { ...local, counter: Math.max(local.counter, server.counter) },
    };
  }
  const account = local.account.endsWith(CONFLICT_SUFFIX)
    ? local.account
    : (local.account + CONFLICT_SUFFIX).slice(0, 256);
  return { action: "copy", value: { ...local, account } };
}
