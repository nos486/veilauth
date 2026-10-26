import { MIGRATIONS, type Migration } from "./migrations.gen.js";

// Same bookkeeping table as `wrangler d1 migrations apply`, so both ways of migrating agree.
const CREATE_TABLE = `CREATE TABLE IF NOT EXISTS d1_migrations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE,
  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
)`;

let ready: Promise<void> | null = null;

/**
 * Creates or upgrades the D1 schema on the first request each isolate handles (D-051). Later
 * calls reuse the result; a failure is retried on the next request.
 */
export function ensureSchema(db: D1Database): Promise<void> {
  const check =
    ready ??
    applyMigrations(db, MIGRATIONS).then(
      () => undefined,
      (e: unknown) => {
        ready = null;
        throw e;
      },
    );
  ready = check;
  return check;
}

/** Applies each pending migration atomically, in file order. Safe to run from many isolates. */
export async function applyMigrations(
  db: D1Database,
  migrations: readonly Migration[],
): Promise<number> {
  await db.prepare(CREATE_TABLE).run();
  const { results } = await db.prepare("SELECT name FROM d1_migrations").all<{ name: string }>();
  const applied = new Set(results.map((r) => r.name));
  let count = 0;
  for (const m of migrations) {
    if (applied.has(m.name)) continue;
    try {
      // A D1 batch is one transaction: the migration and its record commit together or not at all.
      await db.batch([
        ...m.statements.map((s) => db.prepare(s)),
        db.prepare("INSERT INTO d1_migrations (name) VALUES (?)").bind(m.name),
      ]);
      count++;
    } catch (e: unknown) {
      // Another isolate may have applied it at the same moment.
      const done = await db
        .prepare("SELECT 1 AS ok FROM d1_migrations WHERE name = ?")
        .bind(m.name)
        .first();
      if (done === null) throw e;
    }
  }
  return count;
}

/** For tests: forget that this isolate has checked the schema. */
export function resetSchemaCheck(): void {
  ready = null;
}
