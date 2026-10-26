// Starts the Worker locally for the E2E run: fresh D1 state, migrations, dev secrets, built web app.
import { spawn, spawnSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";

const port = process.argv[2] ?? "8799";
const worker = fileURLToPath(new URL("../../worker/", import.meta.url));
const state = ".wrangler/e2e-state";

function run(cmd, args) {
  const r = spawnSync(cmd, args, { cwd: worker, stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

if (!existsSync(fileURLToPath(new URL("../dist/index.html", import.meta.url)))) {
  process.stderr.write("apps/web/dist is missing: run `pnpm build` first\n");
  process.exit(1);
}
rmSync(new URL(state, `file://${worker}`), { recursive: true, force: true });
if (!existsSync(`${worker}.dev.vars`)) run("node", ["scripts/generate-secrets.mjs", "--dev"]);
run("npx", ["wrangler", "d1", "migrations", "apply", "DB", "--local", "--persist-to", state]);
const child = spawn("npx", ["wrangler", "dev", "--port", port, "--persist-to", state], {
  cwd: worker,
  stdio: "inherit",
});
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    child.kill(sig);
    process.exit(0);
  });
}
child.on("exit", (code) => process.exit(code ?? 0));
