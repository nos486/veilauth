import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

async function testSecrets(): Promise<Record<string, string>> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const b64u = (n: number) =>
    Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");
  return {
    JWT_PRIVATE_JWK: JSON.stringify(jwk),
    FAKE_SALT_SECRET: b64u(32),
    IP_HASH_SECRET: b64u(32),
    TURNSTILE_SECRET_KEY: "",
  };
}

export default defineConfig(async () => {
  const migrations = await readD1Migrations("./migrations");
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: { bindings: { TEST_MIGRATIONS: migrations, ...(await testSecrets()) } },
      }),
    ],
    test: { include: ["test/**/*.test.ts"], setupFiles: ["./test/setup.ts"], testTimeout: 30_000 },
  };
});
