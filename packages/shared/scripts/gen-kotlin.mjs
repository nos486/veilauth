// Generates the Android API models (apps/android/core/api) from spec/api.openapi.yaml.
//   node scripts/gen-kotlin.mjs           write the file
//   node scripts/gen-kotlin.mjs --check   fail if the committed file is out of date
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const specPath = resolve(root, "spec/api.openapi.yaml");
const outPath = resolve(
  root,
  "apps/android/core/api/src/main/kotlin/app/zk2fa/core/api/ApiModels.kt",
);

const spec = parse(readFileSync(specPath, "utf8"));
const schemas = spec.components.schemas;

const pascal = (s) => s.charAt(0).toUpperCase() + s.slice(1);
const enumEntry = (v) => v.toUpperCase().replace(/[^A-Z0-9]+/g, "_");
const refName = (ref) => ref.replace("#/components/schemas/", "");

/** Classes and enums emitted so far, in order. */
const out = [];
const emitted = new Set();

function isNullSchema(s) {
  return s.type === "null";
}

/** Follows `$ref` chains to the schema that carries `type` / `enum`. */
function resolveSchema(s) {
  let cur = s;
  while (cur.type === undefined && cur.enum === undefined && cur.$ref !== undefined) {
    cur = schemas[refName(cur.$ref)];
  }
  return cur;
}

/** Returns [kotlinType, nullable]. `hint` names inline objects and enums. */
function typeOf(s, hint) {
  if (s.anyOf !== undefined) {
    const nonNull = s.anyOf.filter((x) => !isNullSchema(x));
    if (nonNull.length !== 1) throw new Error(`unsupported anyOf at ${hint}`);
    return [typeOf(nonNull[0], hint)[0], true];
  }
  if (Array.isArray(s.type)) {
    const nonNull = s.type.filter((t) => t !== "null");
    if (nonNull.length !== 1) throw new Error(`unsupported type list at ${hint}`);
    return [typeOf({ ...s, type: nonNull[0] }, hint)[0], s.type.includes("null")];
  }
  if (s.$ref !== undefined && s.type === undefined) {
    const name = refName(s.$ref);
    const target = schemas[name];
    const resolved = resolveSchema(target);
    if (resolved.type === "object" || resolved.enum !== undefined) {
      emitSchema(name, target);
      return [name, false];
    }
    return typeOf(resolved, name);
  }
  if (s.enum !== undefined) {
    emitEnum(hint, s.enum);
    return [hint, false];
  }
  switch (s.type) {
    case "string":
      return ["String", false];
    case "integer":
      return ["Long", false];
    case "boolean":
      return ["Boolean", false];
    case "array":
      return [`List<${typeOf(s.items, `${hint}Item`)[0]}>`, false];
    case "object":
      emitObject(hint, s);
      return [hint, false];
    default:
      throw new Error(`unsupported schema at ${hint}: ${JSON.stringify(s)}`);
  }
}

function emitEnum(name, values) {
  if (emitted.has(name)) return;
  emitted.add(name);
  const entries = values.map((v) => `    @SerialName("${v}")\n    ${enumEntry(v)},`).join("\n");
  out.push(`@Serializable\npublic enum class ${name} {\n${entries}\n}`);
}

function emitObject(name, s) {
  if (emitted.has(name)) return;
  emitted.add(name);
  const required = new Set(s.required ?? []);
  const props = Object.entries(s.properties ?? {}).map(([prop, ps]) => {
    const [type, nullable] = typeOf(ps, name + pascal(prop));
    // Optional fields default to null and are left out of the JSON (encodeDefaults = false);
    // required nullable fields have no default, so an explicit null is always sent.
    if (!required.has(prop)) return `    val ${prop}: ${type}? = null,`;
    return `    val ${prop}: ${type}${nullable ? "?" : ""},`;
  });
  out.push(`@Serializable\npublic data class ${name}(\n${props.join("\n")}\n)`);
}

function emitSchema(name, s) {
  const resolved = resolveSchema(s);
  if (resolved.enum !== undefined) emitEnum(name, resolved.enum);
  else if (resolved.type === "object") emitObject(name, resolved);
}

for (const [name, s] of Object.entries(schemas)) emitSchema(name, s);

const paths = Object.keys(spec.paths)
  .map((p) => {
    const constName = p
      .replace(/^\/api\/v1\/?/, "")
      .replace(/\{[^}]+\}/g, "by_id")
      .replace(/[^A-Za-z0-9]+/g, "_")
      .replace(/^_|_$/g, "")
      .toUpperCase();
    return `    public const val ${constName}: String = "${p}"`;
  })
  .join("\n");

const file = `// Generated from spec/api.openapi.yaml by packages/shared/scripts/gen-kotlin.mjs. Do not edit.
// Regenerate with \`pnpm --filter @zk2fa/shared kotlin\`; CI runs \`kotlin:check\`.
@file:Suppress("ktlint")

package app.zk2fa.core.api

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

public object ApiPaths {
${paths}
}

${out.join("\n\n")}
`;

if (process.argv.includes("--check")) {
  let current = "";
  try {
    current = readFileSync(outPath, "utf8");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  if (current !== file) {
    console.error(
      "apps/android/core/api ApiModels.kt is out of date with spec/api.openapi.yaml. Run: pnpm --filter @zk2fa/shared kotlin",
    );
    process.exit(1);
  }
  console.log("Kotlin API models are up to date.");
} else {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, file);
  console.log(`wrote ${outPath}`);
}
