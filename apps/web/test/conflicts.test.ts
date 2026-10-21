import { describe, expect, it } from "vitest";
import { newTokenItem } from "../src/lib/tokens";
import { CONFLICT_SUFFIX, resolveTokenConflict } from "../src/sync/conflicts";

const t = newTokenItem(
  {
    type: "totp",
    issuer: "Example",
    account: "bob",
    secret: "JBSWY3DPEHPK3PXP", // gitleaks:allow (public test value)
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    counter: 0,
  },
  1,
);

describe("resolveTokenConflict", () => {
  it("drops identical edits", () => {
    expect(resolveTokenConflict({ ...t }, { ...t })).toEqual({ action: "same" });
  });
  it("merges HOTP by the higher counter", () => {
    const h = { ...t, type: "hotp" as const };
    expect(resolveTokenConflict({ ...h, counter: 3 }, { ...h, counter: 8 })).toEqual({
      action: "merge",
      value: { ...h, counter: 8 },
    });
  });
  it("keeps a marked copy otherwise, without stacking suffixes", () => {
    const r = resolveTokenConflict({ ...t, notes: "mine" }, { ...t, notes: "theirs" });
    expect(r).toEqual({
      action: "copy",
      value: { ...t, notes: "mine", account: `bob${CONFLICT_SUFFIX}` },
    });
    const again = resolveTokenConflict({ ...t, account: `bob${CONFLICT_SUFFIX}` }, t);
    expect(again.action === "copy" && again.value.account).toBe(`bob${CONFLICT_SUFFIX}`);
  });
});
