import { describe, expect, it } from "vitest";
import { buildDocument } from "../src/generate-openapi.js";
import { LoginRequest, PushRequest, ROUTES, SyncQuery } from "../src/index.js";

const id = "0192d5f0-6a3c-7c1e-8b2a-3f4e5d6c7b8a";
const key = "A".repeat(43);

describe("schemas", () => {
  it("accepts a valid login", () => {
    expect(
      LoginRequest.safeParse({
        email: "a@b.c",
        authKey: key,
        device: { id, platform: "web", nameEnc: null },
      }).success,
    ).toBe(true);
  });

  it.each([
    ["padded key", { authKey: `${"A".repeat(42)}=` }],
    ["uppercase id", { device: { id: id.toUpperCase(), platform: "web", nameEnc: null } }],
    ["unknown platform", { device: { id, platform: "ios", nameEnc: null } }],
  ])("rejects %s", (_n, patch) => {
    const base = { email: "a@b.c", authKey: key, device: { id, platform: "web", nameEnc: null } };
    expect(LoginRequest.safeParse({ ...base, ...patch }).success).toBe(false);
  });

  it("caps pushes at 200 changes", () => {
    const change = { id, kind: "token", blob: null, baseRevision: 0 };
    expect(
      PushRequest.safeParse({ changes: Array.from({ length: 200 }, () => change) }).success,
    ).toBe(true);
    expect(
      PushRequest.safeParse({ changes: Array.from({ length: 201 }, () => change) }).success,
    ).toBe(false);
  });

  it("coerces the since query", () => {
    expect(SyncQuery.parse({ since: "42" })).toEqual({ since: 42 });
    expect(SyncQuery.parse({})).toEqual({ since: 0 });
  });
});

describe("OpenAPI document", () => {
  it("covers every route", () => {
    const doc = buildDocument() as { paths: Record<string, Record<string, unknown>> };
    for (const route of Object.values(ROUTES)) {
      expect(doc.paths[`/api/v1${route.path}`]?.[route.method]).toBeDefined();
    }
  });
});
