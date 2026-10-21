import type { Context } from "hono";
import type { z } from "zod";
import type { AppEnv } from "../app-env.js";
import { ApiError } from "./errors.js";

export const MAX_BODY_BYTES = 2 * 1024 * 1024;

/** Reads and validates a JSON body. Validation errors name fields only, never values. */
export async function body<T extends z.ZodType>(
  c: Context<AppEnv>,
  schema: T,
): Promise<z.infer<T>> {
  const type = c.req.header("content-type") ?? "";
  if (!type.toLowerCase().startsWith("application/json")) {
    throw new ApiError("BAD_REQUEST", { detail: "Content-Type must be application/json." });
  }
  const declared = Number(c.req.header("content-length") ?? "0");
  if (declared > MAX_BODY_BYTES) throw new ApiError("PAYLOAD_TOO_LARGE");
  const text = await c.req.text();
  if (text.length > MAX_BODY_BYTES) throw new ApiError("PAYLOAD_TOO_LARGE");
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (e: unknown) {
    if (e instanceof SyntaxError)
      throw new ApiError("BAD_REQUEST", { detail: "Body is not valid JSON." });
    throw e;
  }
  return parse(schema, json);
}

export function parse<T extends z.ZodType>(schema: T, value: unknown): z.infer<T> {
  const result = schema.safeParse(value);
  if (!result.success) {
    const fields = [
      ...new Set(result.error.issues.map((i) => i.path.map(String).join(".") || "(root)")),
    ].slice(0, 10);
    throw new ApiError("BAD_REQUEST", { detail: `Invalid fields: ${fields.join(", ")}` });
  }
  return result.data;
}
