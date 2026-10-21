#!/usr/bin/env node
// Creates the D1 databases (if missing) and writes their ids into wrangler.jsonc.
//   node scripts/setup-cloudflare.mjs staging production
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const PLACEHOLDER = {
  staging: "REPLACE_WITH_STAGING_D1_ID",
  production: "REPLACE_WITH_PRODUCTION_D1_ID",
};
const wrangler = (...a) =>
  execFileSync("npx", ["wrangler", ...a], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });

const envs = process.argv.slice(2);
if (envs.length === 0 || envs.some((e) => !(e in PLACEHOLDER))) {
  console.error("usage: setup-cloudflare.mjs staging [production]");
  process.exit(1);
}

let config = readFileSync("wrangler.jsonc", "utf8");
for (const env of envs) {
  const name = `veilauth-${env}`;
  const list = () => JSON.parse(wrangler("d1", "list", "--json"));
  let db = list().find((d) => d.name === name);
  if (db === undefined) {
    console.log(`creating D1 database ${name}`);
    wrangler("d1", "create", name);
    db = list().find((d) => d.name === name);
  }
  if (db === undefined) throw new Error(`could not find ${name} after creating it`);
  config = config.replace(PLACEHOLDER[env], db.uuid);
  console.log(`${name}: ${db.uuid}`);
}
writeFileSync("wrangler.jsonc", config);
console.log("updated wrangler.jsonc — commit it (database ids are not secret)");
