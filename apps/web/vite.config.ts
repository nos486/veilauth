import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";
import { VitePWA } from "vite-plugin-pwa";

/**
 * Adds Subresource Integrity (sha384) to every script, stylesheet and modulepreload tag in
 * index.html. Runs in generateBundle so it hashes the final, minified output.
 */
function subresourceIntegrity(): Plugin {
  return {
    name: "veilauth-sri",
    apply: "build",
    enforce: "post",
    generateBundle: {
      order: "post",
      handler(_options, bundle) {
        const page = bundle["index.html"];
        if (page?.type !== "asset" || typeof page.source !== "string") return;
        page.source = page.source.replace(
          /<(script|link)\b([^>]*?)\s(src|href)="\/([^"]+)"([^>]*)>/g,
          (tag: string, el: string, before: string, attr: string, path: string, after: string) => {
            const out = bundle[path];
            if (!out || /\sintegrity=/.test(tag)) return tag;
            const content = out.type === "chunk" ? out.code : out.source;
            const hash = createHash("sha384").update(content).digest("base64");
            return `<${el}${before} ${attr}="/${path}" integrity="sha384-${hash}"${after}>`;
          },
        );
      },
    },
  };
}

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")) as {
  version: string;
};

function buildCommit(): string {
  if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA.slice(0, 12);
  try {
    return execFileSync("git", ["rev-parse", "--short=12", "HEAD"], { encoding: "utf8" }).trim();
  } catch {
    return "dev";
  }
}

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
    __BUILD_COMMIT__: JSON.stringify(buildCommit()),
  },
  plugins: [
    react(),
    tailwindcss(),
    subresourceIntegrity(),
    VitePWA({
      // docs/DECISIONS.md D-018: we decide when to activate a new build (never while unlocked).
      registerType: "prompt",
      injectRegister: false,
      manifest: {
        name: "veilauth",
        short_name: "veilauth",
        description: "Zero-knowledge two-factor authenticator",
        start_url: "/",
        scope: "/",
        display: "standalone",
        background_color: "#0b0b12",
        theme_color: "#4f46e5",
        icons: [
          { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
          { src: "/icon-512.png", sizes: "512x512", type: "image/png" },
          {
            src: "/icon-maskable-512.png",
            sizes: "512x512",
            type: "image/png",
            purpose: "maskable",
          },
        ],
      },
      workbox: {
        globPatterns: ["**/*.{js,css,html,svg,png,webmanifest,wasm}"],
        globIgnores: ["turnstile.*", "SHA256SUMS"],
        navigateFallback: "/index.html",
        navigateFallbackDenylist: [/^\/api\//, /^\/turnstile/],
        // The API is never cached by the service worker.
        runtimeCaching: [],
        cleanupOutdatedCaches: true,
        // No importScripts in the worker: Trusted Types applies there too.
        inlineWorkboxRuntime: true,
        maximumFileSizeToCacheInBytes: 6 * 1024 * 1024,
      },
    }),
  ],
  worker: { format: "es" },
  build: {
    target: "es2022",
    sourcemap: false,
    modulePreload: { polyfill: false },
  },
  server: {
    proxy: { "/api": "http://127.0.0.1:8787" },
  },
});
