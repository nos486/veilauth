// Post-build: verifies the Subresource Integrity hashes in dist/index.html and writes
// dist/SHA256SUMS for every published file, so anyone can compare what they are served with
// the release (docs/DECISIONS.md D-041).
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const dist = new URL("../dist/", import.meta.url).pathname;

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

const html = readFileSync(join(dist, "index.html"), "utf8");
let checked = 0;
for (const m of html.matchAll(/(?:src|href)="\/([^"]+)" integrity="sha384-([^"]+)"/g)) {
  const [, path, expected] = m;
  const actual = createHash("sha384")
    .update(readFileSync(join(dist, path)))
    .digest("base64");
  if (actual !== expected) {
    process.stderr.write(`SRI mismatch for ${path}\n`);
    process.exit(1);
  }
  checked++;
}
if (checked === 0) {
  process.stderr.write("index.html has no integrity attributes\n");
  process.exit(1);
}

const files = walk(dist)
  .map((p) => relative(dist, p))
  .filter((p) => p !== "SHA256SUMS")
  .sort();
const lines = files.map(
  (f) =>
    `${createHash("sha256")
      .update(readFileSync(join(dist, f)))
      .digest("hex")}  ${f}`,
);
writeFileSync(join(dist, "SHA256SUMS"), `${lines.join("\n")}\n`);
process.stdout.write(
  `SRI verified for ${String(checked)} tags; SHA256SUMS lists ${String(files.length)} files\n`,
);
