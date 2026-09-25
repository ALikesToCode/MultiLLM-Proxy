import { readdir, readFile } from "node:fs/promises";

const DIRECTORY = new URL("../intelligence-migrations/", import.meta.url);

export async function migrationNames() {
  return (await readdir(DIRECTORY)).filter(name => /^\d{4}_[a-z0-9_]+\.sql$/.test(name)).sort();
}

/** Apply the D1 migrations in order, optionally skipping some, as `wrangler d1 migrations apply` would. */
export async function applyMigrations(db, { skip = [] } = {}) {
  for (const name of await migrationNames()) {
    if (skip.includes(name)) continue;
    const sql = (await readFile(new URL(name, DIRECTORY), "utf8")).replace(/^--.*$/gm, "");
    for (const statement of sql.split(";").filter(item => item.trim())) await db.prepare(statement).run();
  }
}
