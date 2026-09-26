import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import { checkMigrations, destructiveChanges, localMigrations, numberingProblems, sqlStatements }
  from "../scripts/verify_d1_migrations.mjs";
import { buildIdFromBundle, cloudflareApi, collectStatus, describeVersion, evaluate, readyVerdict, renderMarkdown, renderText,
  verifyUntilSettled, wranglerFailure } from "../scripts/deploy_status.mjs";

const MIGRATIONS = new URL("../intelligence-migrations/", import.meta.url);
const COMMIT = "a".repeat(40);
const OLD_COMMIT = "b".repeat(40);
const FINGERPRINT = "c".repeat(64);
const TOKEN = "synthetic-token-not-real";
const ACCOUNT = "0".repeat(32);

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

test("version details carry the commit from the deploy tag", () => {
  const tagged = describeVersion({ id: "v1", metadata: { created_on: "2026-09-26T00:00:00Z", source: "wrangler" },
    annotations: { "workers/tag": COMMIT, "workers/message": "run 1" } }, 100);
  assert.equal(tagged.commit, COMMIT);
  assert.equal(tagged.commit_source, "version tag");
  const secret = describeVersion({ id: "v2", metadata: { source: "api" }, annotations: { "workers/triggered_by": "secret" } }, 100);
  assert.equal(secret.commit, null);
  assert.equal(secret.triggered_by, "secret");
});

test("bundle fingerprints, readiness and Wrangler failures are parsed", () => {
  assert.equal(buildIdFromBundle(`var x = 1;\nvar BUILD_ID = "${FINGERPRINT}";\n`), FINGERPRINT);
  assert.equal(buildIdFromBundle('const BUILD_ID = "development-unbuilt";'), null);
  assert.deepEqual(readyVerdict(200, { status: "healthy" }), { ok: true, status: 200, detail: "ready" });
  assert.equal(readyVerdict(503, { status: "not_ready", reason: "d1_schema_missing", missing_tables: ["auto_routes"] }).detail,
    "D1 schema is missing tables: auto_routes");
  assert.equal(readyVerdict(503, null).detail, "HTTP 503");
  const failure = Object.assign(new Error("Command failed"), {
    stderr: "\u001b[33m▲ [WARNING] something\u001b[0m\n\u001b[31m✘ [ERROR] Authentication error [code: 10000]\u001b[0m\n" });
  assert.equal(wranglerFailure(failure), "Authentication error [code: 10000]");
});

test("the API client needs both credentials and never reports the token", async () => {
  assert.equal(cloudflareApi({ CLOUDFLARE_API_TOKEN: TOKEN }), null);
  assert.equal(cloudflareApi({ CLOUDFLARE_API_TOKEN: TOKEN, CLOUDFLARE_ACCOUNT_ID: "not-an-id" }), null);
  let seen;
  const api = cloudflareApi({ CLOUDFLARE_API_TOKEN: TOKEN, CLOUDFLARE_ACCOUNT_ID: ACCOUNT }, async (url, init) => {
    seen = { url, authorization: init.headers.Authorization };
    return new Response("denied", { status: 403 });
  });
  await assert.rejects(api("/workers/scripts/x/content/v2"), error => !error.message.includes(TOKEN) && /HTTP 403/.test(error.message));
  assert.equal(seen.url, `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/workers/scripts/x/content/v2`);
  assert.equal(seen.authorization, `Bearer ${TOKEN}`);
});

function fakeCloudflare({ mainCommit = COMMIT, mainSource = "wrangler", knowledgeCommit = COMMIT, pending = 0,
  bundleFingerprint = FINGERPRINT, buildCommit = null, readyStatus = 200 } = {}) {
  const versions = {
    "main-version": { id: "main-version", metadata: { source: mainSource, created_on: "2026-09-26T00:00:00Z" },
      annotations: mainCommit ? { "workers/tag": mainCommit } : {} },
    "knowledge-version": { id: "knowledge-version", metadata: { source: "wrangler", created_on: "2026-09-26T00:00:00Z" },
      annotations: { "workers/tag": knowledgeCommit } },
  };
  const names = localMigrations();
  const run = args => {
    if (args[0] === "deployments") {
      const id = args.at(-1) === "wrangler.jsonc" ? "main-version" : "knowledge-version";
      return JSON.stringify({ created_on: "2026-09-26T00:00:00Z", versions: [{ version_id: id, percentage: 100 }] });
    }
    if (args[0] === "versions") return JSON.stringify(versions[args[2]]);
    if (args[0] === "d1") {
      return JSON.stringify([{ success: true, results: names.slice(0, names.length - pending).map(name => ({ name })) }]);
    }
    throw new Error(`unexpected wrangler ${args.join(" ")}`);
  };
  const fetchImpl = async url => {
    const { pathname } = new URL(url);
    if (pathname === "/ready") {
      return Response.json(readyStatus === 200 ? { status: "healthy" }
        : { status: "not_ready", reason: "d1_schema_missing", missing_tables: ["auto_routes"] }, { status: readyStatus });
    }
    if (pathname.endsWith("/content/v2")) return new Response(`var BUILD_ID = "${bundleFingerprint}";`);
    if (pathname.endsWith("/builds/builds")) {
      return Response.json({ result: { builds: buildCommit ? { "main-version": { build_trigger_metadata: { commit_hash: buildCommit } } } : {} } });
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  return { run, fetchImpl, api: cloudflareApi({ CLOUDFLARE_API_TOKEN: TOKEN, CLOUDFLARE_ACCOUNT_ID: ACCOUNT }, fetchImpl) };
}

const LOCAL = { commit: COMMIT, dirty: false, fingerprint: FINGERPRINT };
const collect = cloudflare => collectStatus({ ...cloudflare, origin: "https://gateway.example", database: "db", local: LOCAL });

test("a deploy by Actions verifies migrations, /ready, both Workers and the fingerprint", async () => {
  const status = await collect(fakeCloudflare());
  const checks = evaluate(status, { commit: COMMIT, mainWorker: "actions" });
  assert.deepEqual(checks.map(check => [check.name, check.state]), [["D1 migrations", "pass"], ["/ready", "pass"],
    ["Knowledge Worker", "pass"], ["Main Worker", "pass"], ["Release fingerprint", "pass"]]);
  for (const output of [renderText(status, checks), renderMarkdown(status, checks), JSON.stringify(status)]) {
    assert.ok(!output.includes(TOKEN));
    assert.ok(!output.includes(ACCOUNT));
  }
  assert.match(renderText(status, checks),
    /Main Worker +multillm-proxy: version main-ver at 100% from Wrangler, .*commit aaaaaaaaaaaa \(version tag\), fingerprint cccccccccccc \(matches checkout\)/);
});

test("pending migrations, a missing schema and a Workers Builds overwrite fail verification", async () => {
  const status = await collect(fakeCloudflare({ pending: 1, readyStatus: 503, mainCommit: null, mainSource: "workersci",
    buildCommit: OLD_COMMIT, bundleFingerprint: "d".repeat(64) }));
  const checks = Object.fromEntries(evaluate(status, { commit: COMMIT, mainWorker: "actions" }).map(check => [check.name, check]));
  assert.equal(checks["D1 migrations"].state, "fail");
  assert.match(checks["D1 migrations"].detail, /^pending: \d{4}_/);
  assert.equal(checks["/ready"].detail, "503: D1 schema is missing tables: auto_routes");
  assert.equal(checks["Main Worker"].state, "fail");
  assert.match(checks["Main Worker"].detail, /runs bbbbbbbbbbbb, expected aaaaaaaaaaaa \(Workers Builds deployed it/);
  assert.equal(checks["Release fingerprint"].state, "fail");
});

test("with Workers Builds deploying the main Worker a lag is a warning that is retried", async () => {
  const lagging = evaluate(await collect(fakeCloudflare({ mainCommit: null, mainSource: "workersci", buildCommit: OLD_COMMIT,
    bundleFingerprint: "d".repeat(64) })), { commit: COMMIT, mainWorker: "workers-builds" });
  const main = lagging.find(check => check.name === "Main Worker (Workers Builds)");
  assert.equal(main.state, "warn");
  assert.equal(main.retry, true);
  const built = evaluate(await collect(fakeCloudflare({ mainCommit: null, mainSource: "workersci", buildCommit: COMMIT })),
    { commit: COMMIT, mainWorker: "workers-builds" });
  assert.equal(built.find(check => check.name === "Main Worker (Workers Builds)").state, "pass");
  const sameSource = evaluate(await collect(fakeCloudflare({ mainCommit: null, mainSource: "workersci" })),
    { commit: COMMIT, mainWorker: "workers-builds" });
  assert.match(sameSource.find(check => check.name === "Main Worker (Workers Builds)").detail, /bundle fingerprint matches/);
});

test("verification retries until the checks settle or the wait runs out", async () => {
  const states = [fakeCloudflare({ readyStatus: 503 }), fakeCloudflare({ readyStatus: 503 }), fakeCloudflare()];
  let clock = 0;
  let calls = 0;
  const options = { evaluateOptions: { commit: COMMIT, mainWorker: "actions" }, now: () => clock,
    sleep: async ms => { clock += ms; } };
  const settled = await verifyUntilSettled({ ...options, waitSeconds: 300, collect: () => collect(states[Math.min(calls++, 2)]) });
  assert.equal(calls, 3);
  assert.ok(settled.checks.every(check => check.state === "pass"));
  clock = 0;
  calls = 0;
  const expired = await verifyUntilSettled({ ...options, waitSeconds: 30, collect: () => { calls += 1; return collect(states[0]); } });
  assert.equal(expired.checks.find(check => check.name === "/ready").state, "fail");
  assert.ok(calls >= 2 && calls <= 4);
});
