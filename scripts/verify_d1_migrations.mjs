/**
 * Guards for the D1 migrations in intelligence-migrations/.
 *
 *   node scripts/verify_d1_migrations.mjs --check              Static checks, no network (CI).
 *   node scripts/verify_d1_migrations.mjs --pending [database]  Print migrations not yet applied remotely.
 *   node scripts/verify_d1_migrations.mjs [database]            Fail unless every file is applied remotely.
 *
 * The static check fails when a file name is malformed, when numbering has a gap or a
 * duplicate (two branches that each added the same number), or when a migration drops or
 * renames a table or column without a `-- destructive-migration: <reason>` line. Migrations
 * are applied before the code that needs them, so they must stay safe for the code that is
 * still running. Run the remote check after `wrangler d1 migrations apply` and before any
 * Worker deploy.
 */
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const DIRECTORY = new URL("../intelligence-migrations/", import.meta.url);
const DEFAULT_DATABASE = "multillm-intelligence";
export const MIGRATION_NAME = /^(\d{4})_[a-z0-9_]+\.sql$/;
const MARKER = /^--[ \t]*destructive-migration:[ \t]*(\S.*)?$/m;
const DESTRUCTIVE = [
  [/^DROP\s+TABLE\b/i, "drops a table"],
  [/^ALTER\s+TABLE\b.*\bDROP\b/i, "drops a column"],
  [/^ALTER\s+TABLE\b.*\bRENAME\b/i, "renames a table or column"],
];

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

const pad = number => String(number).padStart(4, "0");

/** Problems with the migration file names: format, duplicate numbers and gaps. */
export function numberingProblems(names) {
  const problems = [];
  const byNumber = new Map();
  for (const name of names.filter(item => item.endsWith(".sql")).sort()) {
    const match = MIGRATION_NAME.exec(name);
    if (!match) {
      problems.push(`${name}: rename it to NNNN_lowercase_words.sql. Wrangler would apply it, but these checks would not see it.`);
      continue;
    }
    const number = Number(match[1]);
    byNumber.set(number, [...(byNumber.get(number) ?? []), name]);
  }
  if (byNumber.has(0)) problems.push("Migration numbers start at 0001.");
  for (const [number, files] of byNumber) {
    if (files.length > 1) {
      problems.push(`${files.join(" and ")} share number ${pad(number)}. Renumber the one that is not yet applied to the next free number.`);
    }
  }
  const missing = [];
  for (let number = 1; number <= Math.max(0, ...byNumber.keys()); number += 1) {
    if (!byNumber.has(number)) missing.push(pad(number));
  }
  if (missing.length) problems.push(`Migration numbers must run from 0001 without gaps; missing ${missing.join(", ")}.`);
  return problems;
}

/** Split SQL into statements with comments and string literals removed and whitespace collapsed. */
export function sqlStatements(sql) {
  const statements = [];
  let current = "";
  const finish = () => {
    const statement = current.replace(/\s+/g, " ").trim();
    if (statement) statements.push(statement);
    current = "";
  };
  for (let index = 0; index < sql.length;) {
    const char = sql[index];
    const next = sql[index + 1];
    if (char === "-" && next === "-") {
      const end = sql.indexOf("\n", index);
      index = end < 0 ? sql.length : end;
      current += " ";
    } else if (char === "/" && next === "*") {
      const end = sql.indexOf("*/", index + 2);
      index = end < 0 ? sql.length : end + 2;
      current += " ";
    } else if (char === "'") {
      let end = index + 1;
      while (end < sql.length && !(sql[end] === "'" && sql[end + 1] !== "'")) end += sql[end] === "'" ? 2 : 1;
      index = end + 1;
      current += "''";
    } else if (char === ";") {
      finish();
      index += 1;
    } else {
      current += char;
      index += 1;
    }
  }
  finish();
  return statements;
}

/** Statements that drop or rename a table or column, which running code may still use. */
export function destructiveChanges(sql) {
  const changes = [];
  for (const statement of sqlStatements(sql)) {
    const rule = DESTRUCTIVE.find(([pattern]) => pattern.test(statement));
    if (rule) changes.push({ change: rule[1], statement: statement.length > 120 ? `${statement.slice(0, 117)}...` : statement });
  }
  return changes;
}

/** Static checks over a directory listing; `read(name)` returns a file's SQL. */
export function checkMigrations(names, read) {
  const problems = numberingProblems(names);
  const allowed = [];
  for (const name of names.filter(item => MIGRATION_NAME.test(item)).sort()) {
    const sql = read(name);
    const changes = destructiveChanges(sql);
    if (!changes.length) continue;
    const marker = MARKER.exec(sql);
    if (marker?.[1]) {
      allowed.push({ name, reason: marker[1].trim(), changes });
    } else {
      for (const { change, statement } of changes) {
        problems.push(`${name} ${change} (${statement}). Migrations run before the code that needs them, so keep them additive, `
          + "or add a `-- destructive-migration: <reason>` line once no deployed code uses it.");
      }
    }
  }
  return { files: names.filter(item => MIGRATION_NAME.test(item)).sort(), problems, allowed };
}

export function localMigrations(directory = DIRECTORY) {
  return readdirSync(directory).filter(name => MIGRATION_NAME.test(name)).sort();
}

export function remoteAppliedMigrations(database, run = defaultRun) {
  return appliedFromWrangler(run(["d1", "execute", database, "--remote", "--json",
    "--command", "SELECT name FROM d1_migrations ORDER BY id"]));
}

function defaultRun(args) {
  return execFileSync("npx", ["--no-install", "wrangler", ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
}

function check() {
  const names = readdirSync(DIRECTORY);
  const result = checkMigrations(names, name => readFileSync(new URL(name, DIRECTORY), "utf8"));
  for (const { name, reason, changes } of result.allowed) {
    console.log(`${name} is marked destructive (${reason}): ${changes.map(item => item.change).join(", ")}.`);
  }
  if (result.problems.length) {
    for (const problem of result.problems) console.error(problem);
    console.error("D1 migration check failed. See docs/deployment-cloudflare.md#migrations.");
    process.exit(1);
  }
  const last = result.files.at(-1) ?? "none";
  console.log(`${result.files.length} D1 migrations checked: numbering is contiguous and unique (last ${last}), changes are additive.`);
}

function remote(database, { listOnly }) {
  const files = localMigrations();
  const applied = remoteAppliedMigrations(database);
  const unknown = pendingMigrations(applied, files);
  if (unknown.length) {
    console.error(`Applied to ${database} but missing locally: ${unknown.join(", ")}. `
      + "An applied migration was renamed or removed; restore its original name.");
  }
  const pending = pendingMigrations(files, applied);
  if (listOnly) {
    for (const name of pending) console.log(name);
    return;
  }
  if (pending.length) {
    console.error(`D1 migrations are not applied to ${database}: ${pending.join(", ")}. Deploy stopped.`);
    process.exit(1);
  }
  console.log(`All ${files.length} D1 migrations are applied to ${database}.`);
}

function main(args) {
  if (args[0] === "--check") return check();
  if (args[0] === "--pending") return remote(args[1] || DEFAULT_DATABASE, { listOnly: true });
  return remote(args[0] || DEFAULT_DATABASE, { listOnly: false });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main(process.argv.slice(2));
