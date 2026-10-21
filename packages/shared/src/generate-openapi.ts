/* Generates spec/api.openapi.yaml from the Zod schemas (Zod's native JSON Schema output, draft 2020-12 = OpenAPI 3.1). */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { stringify } from "yaml";
import { z } from "zod";
import { API_PREFIX, ROUTES } from "./routes.js";
import * as S from "./schemas.js";

const OUT = fileURLToPath(new URL("../../../spec/api.openapi.yaml", import.meta.url));

type Json = Record<string, unknown>;

export function buildDocument(): Json {
  const registry = z.registry<{ id: string }>();
  const names = new Map<z.ZodType, string>();
  for (const [name, schema] of Object.entries(S)) {
    if (schema instanceof z.ZodType && /^[A-Z]/.test(name) && !names.has(schema)) {
      registry.add(schema, { id: name });
      names.set(schema, name);
    }
  }
  const { schemas } = z.toJSONSchema(registry, {
    target: "draft-2020-12",
    io: "input",
    uri: (id) => `#/components/schemas/${id}`,
  });
  for (const s of Object.values(schemas)) {
    delete (s as Json).$schema;
    delete (s as Json).$id;
  }

  const ref = (schema: z.ZodType): Json => {
    const name = names.get(schema);
    if (name === undefined) throw new Error("route schema must be exported from schemas.ts");
    return { $ref: `#/components/schemas/${name}` };
  };
  const json = (schema: z.ZodType): Json => ({ "application/json": { schema: ref(schema) } });
  const error = { description: "Error", content: json(S.ApiError) };

  const paths: Record<string, Record<string, Json>> = {};
  for (const [operationId, route] of Object.entries(ROUTES)) {
    const parameters: Json[] = [];
    if (route.path.includes("{id}")) {
      parameters.push({ name: "id", in: "path", required: true, schema: ref(S.Id) });
    }
    if ("query" in route) {
      for (const [name, field] of Object.entries(route.query.shape)) {
        parameters.push({
          name,
          in: "query",
          required: false,
          schema: z.toJSONSchema(field as z.ZodType, { io: "input" }),
        });
      }
    }
    const op: Json = {
      operationId,
      summary: route.summary,
      ...(route.auth ? { security: [{ bearer: [] }] } : {}),
      ...(parameters.length > 0 ? { parameters } : {}),
      ...("body" in route ? { requestBody: { required: true, content: json(route.body) } } : {}),
      responses: {
        [route.status]:
          route.response === null
            ? { description: "No content" }
            : { description: "OK", content: json(route.response) },
        "400": error,
        "401": error,
        "429": error,
      },
    };
    for (const p of Object.values(op.parameters ?? [])) delete ((p as Json).schema as Json).$schema;
    const path = API_PREFIX + route.path;
    paths[path] = { ...paths[path], [route.method]: op };
  }

  return {
    openapi: "3.1.0",
    info: {
      title: "veilauth API",
      version: "1.0.0",
      description:
        "Zero-knowledge 2FA vault API. Generated from packages/shared; do not edit by hand.",
    },
    servers: [{ url: "/" }],
    paths,
    components: {
      schemas,
      securitySchemes: { bearer: { type: "http", scheme: "bearer", bearerFormat: "JWT" } },
    },
  };
}

function main(): void {
  const text = stringify(buildDocument(), { lineWidth: 0 });
  if (process.argv.includes("--check")) {
    if (readFileSync(OUT, "utf8") !== text) {
      process.stderr.write(
        "spec/api.openapi.yaml is out of date; run pnpm --filter @zk2fa/shared openapi\n",
      );
      process.exit(1);
    }
    return;
  }
  writeFileSync(OUT, text);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
