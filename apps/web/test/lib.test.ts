import { MigrationBatch } from "@zk2fa/otp";
import QRCode from "qrcode";
import { describe, expect, it } from "vitest";
import { hasString, t } from "../src/i18n";
import { decodeQrPixels } from "../src/lib/qr";
import { clockOffset, resetClockOffset, serverNow, setClockOffset } from "../src/lib/time";
import {
  compareTokens,
  isDuplicate,
  matchesSearch,
  newTokenItem,
  parseScannedText,
  tokensToRestore,
} from "../src/lib/tokens";
import { backupFileName } from "../src/screens/Backup";
import { uuidv7 } from "../src/lib/uuid";
import { sameOriginScriptUrl } from "../src/security/trusted-types";

const SECRET = "JBSWY3DPEHPK3PXP"; // gitleaks:allow (public test value)

describe("parseScannedText", () => {
  it("parses otpauth links, one per line", () => {
    const r = parseScannedText(
      `otpauth://totp/GitHub:alice?secret=${SECRET}&issuer=GitHub\n\notpauth://hotp/Bank:bob?secret=${SECRET}&counter=4`,
      new MigrationBatch(),
    );
    expect(r).toMatchObject({ kind: "tokens", skipped: 0 });
    expect(
      r.kind === "tokens" && r.tokens.map((x) => [x.type, x.issuer, x.account, x.counter]),
    ).toEqual([
      ["totp", "GitHub", "alice", 0],
      ["hotp", "Bank", "bob", 4],
    ]);
  });

  it("collects a two-part Google Authenticator export", () => {
    // Two MigrationPayload messages, batch_size 2, batch_id 7, each with one TOTP entry.
    const part = (index: number, name: string) => {
      const secret = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef];
      const otp = [
        0x0a,
        secret.length,
        ...secret,
        0x12,
        name.length,
        ...Array.from(name, (c) => c.charCodeAt(0)),
        0x30,
        0x02,
      ];
      const bytes = [0x0a, otp.length, ...otp, 0x10, 0x01, 0x18, 0x02, 0x20, index, 0x28, 0x07];
      return `otpauth-migration://offline?data=${encodeURIComponent(btoa(String.fromCharCode(...bytes)))}`;
    };
    const batch = new MigrationBatch();
    expect(parseScannedText(part(1, "two"), batch)).toEqual({
      kind: "batch-progress",
      received: 1,
      total: 2,
    });
    const done = parseScannedText(part(0, "one"), batch);
    expect(done.kind === "tokens" && done.tokens.map((x) => x.account)).toEqual(["one", "two"]);
  });

  it("rejects garbage without echoing it", () => {
    expect(() => parseScannedText("hello secret=ABC", new MigrationBatch())).toThrow(
      /^INVALID_URI$/,
    );
  });
});

describe("token helpers", () => {
  const mk = (issuer: string, account: string, favorite = false) => ({
    id: uuidv7(),
    value: {
      ...newTokenItem(
        {
          type: "totp",
          issuer,
          account,
          secret: SECRET,
          algorithm: "SHA1",
          digits: 6,
          period: 30,
          counter: 0,
        },
        1,
      ),
      favorite,
    },
  });

  it("detects duplicates by issuer, account and secret, ignoring trashed tokens", () => {
    const a = mk("GitHub", "Alice");
    const p = {
      type: "totp" as const,
      issuer: "github",
      account: "alice",
      secret: SECRET,
      algorithm: "SHA1" as const,
      digits: 6,
      period: 30,
      counter: 0,
    };
    expect(isDuplicate(p, [a])).toBe(true);
    expect(isDuplicate({ ...p, account: "bob" }, [a])).toBe(false);
    expect(isDuplicate(p, [{ ...a, value: { ...a.value, trashedAt: 5 } }])).toBe(false);
  });

  it("restores only tokens not in the vault yet, once each, out of the trash and folders", () => {
    const inVault = mk("GitHub", "alice");
    const fromBackup = [
      { ...inVault.value, notes: "same token, other notes" },
      { ...mk("GitLab", "alice").value, folderId: uuidv7(), trashedAt: 9 },
      mk("gitlab", "ALICE").value,
    ];
    let n = 0;
    const fresh = tokensToRestore(fromBackup, [inVault], () => `id-${String(++n)}`);
    expect(fresh).toEqual([
      { id: "id-1", value: { ...fromBackup[1], folderId: null, trashedAt: null } },
    ]);
    expect(tokensToRestore(fromBackup, [], uuidv7)).toHaveLength(2);
  });

  it("names backup files by date", () => {
    expect(backupFileName(new Date(Date.UTC(2026, 9, 26, 12)))).toBe(
      "veilauth-backup-2026-10-26.json",
    );
  });

  it("sorts favorites first, then by issuer and account; searches issuer, account and tags", () => {
    const list = [mk("b", "x"), mk("a", "y"), mk("z", "w", true)].sort(compareTokens);
    expect(list.map((x) => x.value.issuer)).toEqual(["z", "a", "b"]);
    expect(matchesSearch(mk("GitHub", "alice"), "HUB")).toBe(true);
    expect(matchesSearch(mk("GitHub", "alice"), "bob")).toBe(false);
  });
});

describe("misc", () => {
  it("decodes a QR code from RGBA pixels", () => {
    const qr = QRCode.create("otpauth://totp/x?secret=" + SECRET, { errorCorrectionLevel: "M" });
    const scale = 4;
    const margin = 4;
    const n = qr.modules.size;
    const size = (n + margin * 2) * scale;
    const px = new Uint8ClampedArray(size * size * 4).fill(255);
    for (let y = 0; y < n; y++)
      for (let x = 0; x < n; x++)
        if (qr.modules.get(y, x))
          for (let dy = 0; dy < scale; dy++)
            for (let dx = 0; dx < scale; dx++) {
              const o = (((y + margin) * scale + dy) * size + (x + margin) * scale + dx) * 4;
              px[o] = px[o + 1] = px[o + 2] = 0;
            }
    expect(decodeQrPixels(px, size, size)).toBe("otpauth://totp/x?secret=" + SECRET);
  });

  it("generates lowercase UUIDv7", () => {
    const id = uuidv7(0x0190_0000_0000);
    expect(id).toMatch(/^01900000-0000-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it("corrects the clock from /time and ignores slow samples", () => {
    resetClockOffset();
    setClockOffset(1000, 61_000, 1200);
    expect(clockOffset()).toBe(59_900);
    expect(serverNow() - Date.now()).toBeGreaterThanOrEqual(59_899);
    setClockOffset(0, 5, 20_000);
    expect(clockOffset()).toBe(59_900);
    resetClockOffset();
  });

  it("only lets same-origin script URLs through the Trusted Types policy", () => {
    expect(sameOriginScriptUrl("/assets/w.js", "https://vault.example")).toBe(
      "https://vault.example/assets/w.js",
    );
    expect(() =>
      sameOriginScriptUrl("https://evil.example/x.js", "https://vault.example"),
    ).toThrow();
    expect(() => sameOriginScriptUrl("//evil.example/x.js", "https://vault.example")).toThrow();
  });

  it("fills placeholders in UI strings", () => {
    expect(t("add.save", { count: 3 })).toBe("Add 3");
    expect(hasString("error.NETWORK")).toBe(true);
    expect(hasString("error.nope")).toBe(false);
  });
});
