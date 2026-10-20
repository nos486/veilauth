import { describe, expect, it } from "vitest";
import { decodeMigrationUri, MigrationBatch, OtpError } from "../src/index.js";
import { vectors } from "./vectors.js";

describe("otpauth-migration:// (Google Authenticator export)", () => {
  for (const v of vectors.migration) {
    it(v.name, () => {
      if (v.error !== undefined) {
        const uris = v.uris;
        expect(() => uris.map(decodeMigrationUri)).toThrow(
          expect.objectContaining({ code: v.error }) as Error,
        );
        return;
      }
      const batch = new MigrationBatch();
      let last: ReturnType<MigrationBatch["add"]> | undefined;
      // Feed in reverse order: batches may be scanned in any order.
      for (const uri of [...v.uris].reverse()) {
        const payload = decodeMigrationUri(uri);
        expect(payload.batchId).toBe(v.batchId);
        last = batch.add(payload);
      }
      expect(last).toEqual({ status: "complete", entries: v.entries });
    });
  }

  it("reports progress and duplicates", () => {
    const v = vectors.migration.find((m) => m.name === "two-part-batch");
    const first = v?.uris[0];
    if (first === undefined) throw new Error("missing vector");
    const batch = new MigrationBatch();
    expect(batch.add(decodeMigrationUri(first))).toEqual({
      status: "incomplete",
      received: 1,
      total: 2,
    });
    expect(batch.add(decodeMigrationUri(first))).toEqual({
      status: "duplicate",
      received: 1,
      total: 2,
    });
  });

  it("rejects mixing exports", () => {
    const single = vectors.migration.find((m) => m.name === "single-payload")?.uris[0];
    const part = vectors.migration.find((m) => m.name === "two-part-batch")?.uris[0];
    if (single === undefined || part === undefined) throw new Error("missing vector");
    const batch = new MigrationBatch();
    batch.add(decodeMigrationUri(part));
    expect(() => batch.add(decodeMigrationUri(single))).toThrow(OtpError);
  });

  it("tolerates a literal '+' turned into a space", () => {
    const uri = vectors.migration[0]?.uris[0];
    if (uri === undefined) throw new Error("missing vector");
    const data = decodeURIComponent(uri.split("data=")[1] ?? "");
    const mangled = `otpauth-migration://offline?data=${data.replace(/\+/g, " ")}`;
    expect(decodeMigrationUri(mangled)).toEqual(decodeMigrationUri(uri));
  });

  it("rejects garbage without throwing anything but OtpError", () => {
    for (const data of [
      "%FF%FF%FF%FF%FF%FF%FF%FF%FF%FF%FF",
      "CgE",
      "!!!!",
      "CP%2F%2F%2F%2F%2F%2F%2F%2F%2F%2Fw%3D%3D",
    ]) {
      expect(() => decodeMigrationUri(`otpauth-migration://offline?data=${data}`)).toThrow(
        OtpError,
      );
    }
  });
});
