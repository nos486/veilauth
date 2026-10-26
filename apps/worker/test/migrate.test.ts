import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { applyMigrations } from "../src/db/migrate.js";
import { MIGRATIONS } from "../src/db/migrations.gen.js";

async function tableNames(): Promise<string[]> {
  const { results } = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name",
  ).all<{ name: string }>();
  return results.map((r) => r.name);
}

async function dropEverything(): Promise<void> {
  await env.DB.exec("PRAGMA foreign_keys = OFF");
  for (const name of await tableNames()) await env.DB.exec(`DROP TABLE "${name}"`);
}

describe("automatic D1 migrations", () => {
  it("bundles exactly the migrations in migrations/", () => {
    expect(MIGRATIONS.map((m) => m.name)).toEqual(env.TEST_MIGRATIONS.map((m) => m.name));
  });

  it("creates the schema on an empty database, then does nothing", async () => {
    const expected = await tableNames();
    await dropEverything();
    expect(await tableNames()).toEqual([]);

    expect(await applyMigrations(env.DB, MIGRATIONS)).toBe(MIGRATIONS.length);
    expect(await tableNames()).toEqual(expected);
    expect(await applyMigrations(env.DB, MIGRATIONS)).toBe(0);
  });

  it("survives two isolates migrating at once", async () => {
    await dropEverything();
    const counts = await Promise.all([
      applyMigrations(env.DB, MIGRATIONS),
      applyMigrations(env.DB, MIGRATIONS),
    ]);
    expect(counts.reduce((a, b) => a + b, 0)).toBe(MIGRATIONS.length);
    const { results } = await env.DB.prepare("SELECT name FROM d1_migrations").all();
    expect(results).toHaveLength(MIGRATIONS.length);
  });

  it("applies a new migration on top of an existing schema", async () => {
    const extra = { name: "9999_test.sql", statements: ["CREATE TABLE extra_test (id TEXT)"] };
    expect(await applyMigrations(env.DB, [...MIGRATIONS, extra])).toBe(1);
    expect(await tableNames()).toContain("extra_test");
    await env.DB.exec("DROP TABLE extra_test");
    await env.DB.prepare("DELETE FROM d1_migrations WHERE name = ?").bind(extra.name).run();
  });
});
