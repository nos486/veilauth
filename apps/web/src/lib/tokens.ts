import type { TokenItem } from "@zk2fa/crypto";
import {
  decodeMigrationUri,
  type MigrationBatch,
  type OtpParams,
  OtpError,
  parseOtpAuthUri,
} from "@zk2fa/otp";

export const TRASH_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

/** A decrypted token as the UI sees it. */
export interface VaultToken {
  id: string;
  value: TokenItem;
}

export function newTokenItem(params: OtpParams, now: number): TokenItem {
  return {
    type: params.type,
    issuer: params.issuer.slice(0, 256),
    account: params.account.slice(0, 256),
    secret: params.secret,
    algorithm: params.algorithm,
    digits: params.digits,
    period: params.period,
    counter: params.counter,
    iconId: null,
    folderId: null,
    tags: [],
    notes: "",
    favorite: false,
    createdAt: now,
    trashedAt: null,
  };
}

export function otpParamsOf(t: TokenItem): OtpParams {
  return {
    type: t.type,
    issuer: t.issuer,
    account: t.account,
    secret: t.secret,
    algorithm: t.algorithm,
    digits: t.digits,
    period: t.period,
    counter: t.counter,
  };
}

/** Same issuer + account + secret (build spec §7.2). */
export function isDuplicate(candidate: OtpParams, existing: readonly VaultToken[]): boolean {
  const key = (p: { issuer: string; account: string; secret: string }) =>
    `${p.issuer.trim().toLowerCase()}\u0000${p.account.trim().toLowerCase()}\u0000${p.secret}`;
  const k = key(candidate);
  return existing.some((t) => t.value.trashedAt === null && key(t.value) === k);
}

/**
 * The backed-up tokens that are not in the vault yet (nor repeated in the backup), as new items
 * with fresh ids. Folders are not part of a backup yet, so folder ids are cleared; trashed
 * tokens come back out of the trash.
 */
export function tokensToRestore(
  backup: readonly TokenItem[],
  existing: readonly VaultToken[],
  newId: () => string,
): VaultToken[] {
  const known = [...existing];
  const fresh: VaultToken[] = [];
  for (const value of backup) {
    if (isDuplicate(otpParamsOf(value), known)) continue;
    const token = { id: newId(), value: { ...value, folderId: null, trashedAt: null } };
    fresh.push(token);
    known.push(token);
  }
  return fresh;
}

/** Favorites first, then issuer and account, case-insensitively. */
export function compareTokens(a: VaultToken, b: VaultToken): number {
  if (a.value.favorite !== b.value.favorite) return a.value.favorite ? -1 : 1;
  const byIssuer = a.value.issuer.localeCompare(b.value.issuer, undefined, { sensitivity: "base" });
  if (byIssuer !== 0) return byIssuer;
  return a.value.account.localeCompare(b.value.account, undefined, { sensitivity: "base" });
}

export function matchesSearch(t: VaultToken, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (q === "") return true;
  return (
    t.value.issuer.toLowerCase().includes(q) ||
    t.value.account.toLowerCase().includes(q) ||
    t.value.tags.some((tag) => tag.toLowerCase().includes(q))
  );
}

export type ScanResult =
  | { kind: "tokens"; tokens: OtpParams[]; skipped: number }
  | { kind: "batch-progress"; received: number; total: number };

/**
 * Turns scanned or pasted text into tokens. Accepts otpauth://, steam:// and Google Authenticator
 * otpauth-migration:// (single or multi-QR batches, collected in `batch`). One URI per line.
 */
export function parseScannedText(text: string, batch: MigrationBatch): ScanResult {
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== "");
  if (lines.length === 0) throw new OtpError("INVALID_URI");
  const tokens: OtpParams[] = [];
  let skipped = 0;
  for (const line of lines) {
    if (/^otpauth-migration:/i.test(line)) {
      const result = batch.add(decodeMigrationUri(line));
      if (result.status !== "complete") {
        return { kind: "batch-progress", received: result.received, total: result.total };
      }
      for (const e of result.entries) {
        if (e.ok) tokens.push(e.value);
        else skipped++;
      }
    } else {
      tokens.push(parseOtpAuthUri(line));
    }
  }
  return { kind: "tokens", tokens, skipped };
}
