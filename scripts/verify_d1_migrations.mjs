/**
 * Fail unless every file in intelligence-migrations/ is recorded as applied in the remote D1
 * database. Run after `wrangler d1 migrations apply` and before any Worker deploy.
 */
import { execFileSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function pendingMigrations(files, applied) {
  const done = new Set(applied);
  return files.filter(name => !done.has(name));
}

export function appliedFromWrangler(output) {
  const batches = JSON.parse(output);
  if (!Array.isArray(batches) || batches.some(batch => batch?.success !== true || !Array.isArray(batch.results))) {
    throw new Error("wrangler did not return migration rows");
  }
  return batches.flatMap(batch => batch.results.map(row => row.name));
}

function main(database) {
  const files = readdirSync(new URL("../intelligence-migrations/", import.meta.url))
    .filter(name => /^\d{4}_[a-z0-9_]+\.sql$/.test(name)).sort();
  const output = execFileSync("npx", ["--no-install", "wrangler", "d1", "execute", database, "--remote", "--json",
    "--command", "SELECT name FROM d1_migrations ORDER BY id"], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
  const pending = pendingMigrations(files, appliedFromWrangler(output));
  if (pending.length) {
    console.error(`D1 migrations are not applied to ${database}: ${pending.join(", ")}. Deploy stopped.`);
    process.exit(1);
  }
  console.log(`All ${files.length} D1 migrations are applied to ${database}.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main(process.argv[2] || "multillm-intelligence");
