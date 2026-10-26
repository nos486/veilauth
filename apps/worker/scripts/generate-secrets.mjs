#!/usr/bin/env node
// Generates the Worker secrets.
//
//   node scripts/generate-secrets.mjs --print   print once, to paste into the Cloudflare dashboard
//   node scripts/generate-secrets.mjs --dev     write .dev.vars for `wrangler dev`
//
// Set the production secrets ONCE: rotating FAKE_SALT_SECRET changes every fake prelogin salt (an
// observer could then tell real accounts from fake ones), and rotating JWT_PRIVATE_JWK logs
// everyone out.
import { existsSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

function b64u(n) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");
}

async function generate() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return {
    JWT_PRIVATE_JWK: JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d }),
    FAKE_SALT_SECRET: b64u(32),
    IP_HASH_SECRET: b64u(32),
  };
}

const args = process.argv.slice(2);
const secrets = await generate();

if (args.includes("--print")) {
  console.log(
    "Paste each value into Workers → veilauth → Settings → Variables and Secrets (type: Secret).",
  );
  console.log("Do not save this output anywhere else.\n");
  for (const [name, value] of Object.entries(secrets)) console.log(`${name}\n${value}\n`);
} else if (args.includes("--dev")) {
  if (existsSync(".dev.vars") && !args.includes("--force")) {
    console.error(".dev.vars already exists (use --force to overwrite)");
    process.exit(1);
  }
  const lines = Object.entries(secrets).map(([k, v]) => `${k}='${v}'`);
  writeFileSync(".dev.vars", `${lines.join("\n")}\n`, { mode: 0o600 });
  console.log("wrote .dev.vars (git-ignored)");
} else {
  console.error("usage: generate-secrets.mjs --print | --dev");
  process.exit(1);
}
