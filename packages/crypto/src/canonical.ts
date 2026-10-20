import { CryptoError } from "./errors.js";

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * RFC 8785 (JCS) for the restricted type set of spec/crypto.md §6.1:
 * plain objects, arrays, strings, booleans, null and safe integers.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value))
        throw new CryptoError("INVALID_ITEM", "only safe integers are allowed");
      return Object.is(value, -0) ? "0" : String(value);
    case "string":
      if (LONE_SURROGATE.test(value))
        throw new CryptoError("INVALID_ITEM", "lone surrogate in string");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
      const proto: unknown = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null)
        throw new CryptoError("INVALID_ITEM", "not a plain object");
      const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
        a < b ? -1 : a > b ? 1 : 0,
      );
      return `{${entries.map(([k, v]) => `${canonicalJson(k)}:${canonicalJson(v)}`).join(",")}}`;
    }
    default:
      throw new CryptoError("INVALID_ITEM", `unsupported JSON type ${typeof value}`);
  }
}
