#!/usr/bin/env node
// Generates the Worker secrets and (optionally) uploads them with `wrangler secret put`.
//
//   node scripts/generate-secrets.mjs --dev               write .dev.vars for `wrangler dev`
//   node scripts/generate-secrets.mjs --env staging       upload to the staging Worker
//   node scripts/generate-secrets.mjs --env production    upload to the production Worker
//
// Values are never printed. Run each deployed environment ONCE: rotating FAKE_SALT_SECRET changes
// every fake prelogin salt (an observer could then tell real accounts from fake ones), and rotating
// JWT_PRIVATE_JWK logs everyone out.
import { execFileSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const TURNSTILE_TEST_SECRET = "1x0000000000000000000000000000000AA"; // Cloudflare's always-pass test secret

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

if (args.includes("--dev")) {
  if (existsSync(".dev.vars") && !args.includes("--force")) {
    console.error(".dev.vars already exists (use --force to overwrite)");
    process.exit(1);
  }
  const lines = Object.entries(secrets).map(([k, v]) => `${k}='${v}'`);
  writeFileSync(".dev.vars", `${lines.join("\n")}\n`, { mode: 0o600 });
  console.log("wrote .dev.vars (git-ignored)");
} else {
  const i = args.indexOf("--env");
  const env = i === -1 ? undefined : args[i + 1];
  if (env !== "staging" && env !== "production") {
    console.error("usage: generate-secrets.mjs --dev | --env staging|production");
    process.exit(1);
  }
  if (env === "staging") secrets.TURNSTILE_SECRET_KEY = TURNSTILE_TEST_SECRET;
  for (const [name, value] of Object.entries(secrets)) {
    execFileSync("npx", ["wrangler", "secret", "put", name, "--env", env], {
      input: value,
      stdio: ["pipe", "inherit", "inherit"],
    });
  }
  console.log(`uploaded ${Object.keys(secrets).join(", ")} to ${env}`);
  if (env === "production") {
    console.log(
      "now run: npx wrangler secret put TURNSTILE_SECRET_KEY --env production   (from the Turnstile dashboard)",
    );
  }
}
