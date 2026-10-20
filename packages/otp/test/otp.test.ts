import { describe, expect, it } from "vitest";
import {
  base32Decode,
  base32Encode,
  generateCode,
  hotp,
  normalizeBase32,
  OtpError,
  parseOtpAuthUri,
  secondsRemaining,
  steam,
  toOtpAuthUri,
  totp,
} from "../src/index.js";
import { hex, vectors } from "./vectors.js";

describe("HOTP (RFC 4226 Appendix D + extras)", () => {
  it.each(vectors.hotp)("counter $counter $algorithm → $code", async (v) => {
    expect(await hotp(hex(v.secretHex), v.counter, v.digits, v.algorithm)).toBe(v.code);
  });
});

describe("TOTP (RFC 6238 Appendix B + extras)", () => {
  it.each(vectors.totp)("t=$timeMs $algorithm/$period/$digits → $code", async (v) => {
    expect(await totp(hex(v.secretHex), v.timeMs, v.period, v.digits, v.algorithm)).toBe(v.code);
  });
});

describe("Steam Guard", () => {
  it.each(vectors.steam)("$secretB32 t=$timeMs → $code", async (v) => {
    expect(await steam(base32Decode(v.secretB32), v.timeMs)).toBe(v.code);
  });

  it("generateCode dispatches steam", async () => {
    const v = vectors.steam[0];
    if (v === undefined) throw new Error("missing vector");
    const params = parseOtpAuthUri(`steam://${v.secretB32}`);
    expect(await generateCode(params, v.timeMs)).toBe(v.code);
  });
});

describe("base32", () => {
  it("round-trips all lengths", () => {
    for (let n = 0; n < 40; n++) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
      expect(base32Decode(base32Encode(bytes))).toEqual(bytes);
    }
  });

  it("matches RFC 4648 §10", () => {
    const cases: [string, string][] = [
      ["", ""],
      ["f", "MY"],
      ["fo", "MZXQ"],
      ["foo", "MZXW6"],
      ["foob", "MZXW6YQ"],
      ["fooba", "MZXW6YTB"],
      ["foobar", "MZXW6YTBOI"],
    ];
    for (const [plain, enc] of cases) {
      expect(base32Encode(new TextEncoder().encode(plain))).toBe(enc);
    }
  });

  it("normalises spacing, case and padding", () => {
    expect(normalizeBase32(" mzxw 6ytb-oi== ")).toBe("MZXW6YTBOI");
  });

  it.each(["MZXW6YTBO1", "M", "MZX", "MZXW6Y", "MZ"])("rejects %s", (s) => {
    expect(() => base32Decode(s)).toThrow(OtpError);
  });
});

describe("otpauth:// parser", () => {
  it.each(vectors.otpauth)("$uri", (v) => {
    if ("expected" in v) {
      expect(parseOtpAuthUri(v.uri)).toEqual(v.expected);
    } else {
      expect(() => parseOtpAuthUri(v.uri)).toThrow(
        expect.objectContaining({ code: v.error }) as Error,
      );
    }
  });

  it("round-trips through toOtpAuthUri", () => {
    for (const v of vectors.otpauth) {
      if (!("expected" in v)) continue;
      const parsed = parseOtpAuthUri(v.uri);
      expect(parseOtpAuthUri(toOtpAuthUri(parsed))).toEqual(parsed);
    }
  });

  it("never echoes the input in error messages", () => {
    const secretish = "otpauth://totp/x?secret=SUPERSECRETVALUE1&digits=99";
    try {
      parseOtpAuthUri(secretish);
      expect.unreachable();
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(OtpError);
      expect((e as Error).message).not.toContain("SUPERSECRET");
    }
  });
});

describe("time helpers", () => {
  it("secondsRemaining", () => {
    expect(secondsRemaining(0, 30)).toBe(30);
    expect(secondsRemaining(29_999, 30)).toBe(1);
    expect(secondsRemaining(30_000, 30)).toBe(30);
  });

  it("rejects negative time", async () => {
    await expect(totp(new Uint8Array(10), -1)).rejects.toThrow(OtpError);
  });
});
