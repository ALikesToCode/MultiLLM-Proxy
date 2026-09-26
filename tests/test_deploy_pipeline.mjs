import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import { checkMigrations, destructiveChanges, localMigrations, numberingProblems, sqlStatements }
  from "../scripts/verify_d1_migrations.mjs";

const MIGRATIONS = new URL("../intelligence-migrations/", import.meta.url);

test("the committed migrations pass the static checks", () => {
  const names = readdirSync(MIGRATIONS);
  const result = checkMigrations(names, name => readFileSync(new URL(name, MIGRATIONS), "utf8"));
  assert.deepEqual(result.problems, []);
  assert.deepEqual(result.files, localMigrations());
});

test("numbering must be well formed, unique and contiguous", () => {
  assert.deepEqual(numberingProblems(["0001_a.sql", "0002_b.sql", "README.md"]), []);
  const [collision] = numberingProblems(["0001_a.sql", "0002_b.sql", "0002_c.sql"]);
  assert.match(collision, /0002_b\.sql and 0002_c\.sql share number 0002/);
  assert.deepEqual(numberingProblems(["0001_a.sql", "0004_d.sql"]),
    ["Migration numbers must run from 0001 without gaps; missing 0002, 0003."]);
  assert.match(numberingProblems(["0001_a.sql", "2_Bad-Name.sql"])[0], /2_Bad-Name\.sql: rename it/);
  assert.ok(numberingProblems(["0000_a.sql", "0001_b.sql"]).includes("Migration numbers start at 0001."));
});

test("statements ignore comments and string literals", () => {
  const sql = "-- don't DROP TABLE here\nCREATE TABLE t (x TEXT CHECK (x != 'DROP TABLE y;'));\n/* ALTER TABLE t RENAME TO u; */\n"
    + "INSERT INTO t VALUES ('it''s');";
  assert.deepEqual(sqlStatements(sql), ["CREATE TABLE t (x TEXT CHECK (x != ''))", "INSERT INTO t VALUES ('')"]);
  assert.deepEqual(destructiveChanges(sql), []);
});

test("drops and renames of tables or columns are destructive; additive changes are not", () => {
  const sql = "DROP TABLE old;\nALTER TABLE users DROP COLUMN legacy;\nALTER TABLE users RENAME TO accounts;\n"
    + "ALTER TABLE accounts RENAME COLUMN a TO b;\nALTER TABLE accounts ADD COLUMN drop_reason TEXT;\n"
    + "DROP INDEX IF EXISTS idx_old;\nCREATE INDEX IF NOT EXISTS idx_new ON accounts(b);";
  assert.deepEqual(destructiveChanges(sql).map(item => item.change),
    ["drops a table", "drops a column", "renames a table or column", "renames a table or column"]);
});

test("a destructive migration needs a marker with a reason", () => {
  const files = {
    "0001_a.sql": "CREATE TABLE a (id TEXT);",
    "0002_b.sql": "ALTER TABLE a DROP COLUMN id;",
    "0003_c.sql": "-- destructive-migration:\nDROP TABLE a;",
    "0004_d.sql": "-- destructive-migration: no deployed code has read a.note since 0002\nALTER TABLE a DROP COLUMN note;",
  };
  const result = checkMigrations(Object.keys(files), name => files[name]);
  assert.equal(result.problems.length, 2);
  assert.match(result.problems[0], /^0002_b\.sql drops a column \(ALTER TABLE a DROP COLUMN id\)/);
  assert.match(result.problems[1], /^0003_c\.sql drops a table/);
  assert.deepEqual(result.allowed.map(item => [item.name, item.reason]),
    [["0004_d.sql", "no deployed code has read a.note since 0002"]]);
});

