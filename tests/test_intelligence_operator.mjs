import assert from "node:assert/strict";
import { lstat, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { handleIntelligenceAuthRequest } from "../worker/intelligence-auth-d1.mjs";
import {
  generateIntegrationCredential, hashIntegrationKey, openRemoteDatabase, runOperator,
} from "../scripts/intelligence_operator.mjs";

const ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
const DATABASE_ID = "00000000-0000-4000-8000-000000000000";
const TARGET = ["--account-id", ACCOUNT_ID, "--database-id", DATABASE_ID];
const KEY = /^mllm_intelligence_[A-Za-z0-9_-]{64}$/;
// Computed with werkzeug.security for the synthetic key and salt below.
const WERKZEUG_HASH = "scrypt:32768:8:1$SyntheticSalt123$5a14093dc370ea970a86be21491d7e3879f45538e91195ff63779154903c8de1"
  + "ea8d8ca599371dcbbcb95e02a8eae49cb1b7935955b562e38600dd1083a5a2b4";
const policy = (overrides = {}) => ({
  version: 1, enabled: false, max_total_tokens: 1000, principal_daily_tokens: 1000,
  global_daily_tokens: 2000, max_inflight: 4, media: {}, ...overrides,
});
const provision = (file, principal = "integration:omni", scopes = "chat,models") => [
  "provision", ...TARGET, "--apply", "--principal", principal, "--scopes", scopes, "--credential-file", file,
];
const auth = (db, body) => handleIntelligenceAuthRequest(new Request("http://intelligence.internal/v1/auth", {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }),
}), { INTELLIGENCE_DB: db });

async function workspace(t) {
  const directory = await mkdtemp(join(tmpdir(), "multillm-operator-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

async function database(t) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  for (const name of ["0001_intelligence.sql", "0002_integration_principals.sql"]) {
    const migration = await readFile(new URL(`../intelligence-migrations/${name}`, import.meta.url), "utf8");
    for (const sql of migration.split(";").map((part) => part.trim()).filter(Boolean)) await db.prepare(sql).run();
  }
  return db;
}

// Runs the CLI with captured streams and a recorded stand-in for the remote opener.
async function run(args, { db, open } = {}) {
  const result = { stdout: "", stderr: "", opened: 0, disposed: 0 };
  const stream = (name) => ({ write(text) { result[name] += text; return true; } });
  result.code = await runOperator(args, {
    stdout: stream("stdout"), stderr: stream("stderr"),
    async openDatabase(target) {
      result.opened += 1;
      assert.deepEqual(target, { accountId: ACCOUNT_ID, databaseId: DATABASE_ID });
      const binding = open ? await open() : db;
      if (!binding) throw new Error("the remote database must not be opened");
      return { db: binding, dispose: async () => { result.disposed += 1; } };
    },
  });
  result.json = JSON.parse(result.code === 0 ? result.stdout : result.stderr);
  return result;
}

test("integration keys are strong and hashed in Werkzeug's scrypt format", async () => {
  assert.equal(await hashIntegrationKey(`mllm_intelligence_${"k".repeat(32)}`, "SyntheticSalt123"), WERKZEUG_HASH);
  const credential = await generateIntegrationCredential();
  assert.match(credential.key, KEY);
  assert.equal(credential.keyPrefix, credential.key.slice(0, 34));
  assert.match(credential.keyHash, /^scrypt:32768:8:1\$[A-Za-z0-9]{16}\$[a-f0-9]{128}$/);
  assert.equal(await hashIntegrationKey(credential.key, credential.keyHash.split("$")[1]), credential.keyHash);
  assert.notEqual((await generateIntegrationCredential()).key, credential.key);
});

test("dry runs validate through the domain handlers without remote calls or files", async (t) => {
  const directory = await workspace(t);
  const policyFile = join(directory, "policy.json");
  const credentialFile = join(directory, "omni.key");
  await writeFile(policyFile, JSON.stringify(policy()));
  const seeded = await run(["seed", ...TARGET, "--policy-file", policyFile]);
  assert.equal(seeded.opened, 0);
  assert.deepEqual(seeded.json, { version: 1, operation: "seed", ok: true, applied: false, valid: true });
  const provisioned = await run(provision(credentialFile).filter((arg) => arg !== "--apply"));
  assert.equal(provisioned.opened, 0);
  assert.deepEqual(provisioned.json, {
    version: 1, operation: "provision", ok: true, applied: false, valid: true,
    principal: "integration:omni", scopes: ["chat", "models"],
  });
  assert.doesNotMatch(provisioned.stdout, /mllm_intelligence_|scrypt/);
  await assert.rejects(lstat(credentialFile), { code: "ENOENT" });
});

test("invalid input is refused before any file or remote call, with sanitized errors", async (t) => {
  const directory = await workspace(t);
  const invalid = join(directory, "invalid.json");
  const oversized = join(directory, "oversized.json");
  const credentialFile = join(directory, "omni.key");
  await writeFile(invalid, JSON.stringify(policy({ max_inflight: 0 })));
  await writeFile(oversized, " ".repeat(256 * 1024 + 1));
  for (const [args, code, error] of [
    [["seed", ...TARGET, "--apply", "--policy-file", invalid], 1, "invalid_policy"],
    [["seed", ...TARGET, "--apply", "--policy-file", oversized], 1, "invalid_policy_file"],
    [["seed", ...TARGET, "--apply", "--policy-file", directory], 1, "invalid_policy_file"],
    [provision(credentialFile, "integration:omni", "chat,admin"), 1, "invalid_request"],
    [provision(credentialFile, "integration:omni", "chat,chat"), 1, "invalid_request"],
    [provision(credentialFile, "admin", "chat"), 1, "invalid_request"],
    [["seed", ...TARGET, "--apply", "--policy", JSON.stringify(policy())], 2, "usage"],
    [["provision", ...TARGET, `mllm_intelligence_${"SECRET".repeat(6)}`], 2, "usage"],
    [["status", ...TARGET, "--apply"], 2, "usage"],
    [["status", "--account-id", "SECRET", "--database-id", DATABASE_ID], 2, "usage"],
    [["sql", ...TARGET, "SELECT 1"], 2, "usage"],
  ]) {
    const result = await run(args);
    assert.deepEqual([result.code, result.json.error, result.opened, result.stdout], [code, error, 0, ""]);
    assert.doesNotMatch(result.stderr, /SECRET|SELECT|admin|max_inflight|mllm_/);
  }
  await assert.rejects(lstat(credentialFile), { code: "ENOENT" });
});

test("provision saves an owner-only key before the domain stores only its hash", async (t) => {
  const directory = await workspace(t);
  const db = await database(t);
  const credentialFile = join(directory, "omni.key");
  let modeAtSubmission;
  const observed = {
    prepare: (...args) => db.prepare(...args),
    async batch(statements) {
      modeAtSubmission = (await stat(credentialFile)).mode & 0o777;
      return db.batch(statements);
    },
  };
  const umask = process.umask(0);
  let result;
  try { result = await run(provision(credentialFile), { db: observed }); }
  finally { process.umask(umask); }
  assert.deepEqual(result.json, {
    version: 1, operation: "provision", ok: true, applied: true, principal: "integration:omni",
    scopes: ["chat", "models"], credentialVersion: 1, credentialFile: "saved",
  });
  assert.deepEqual([modeAtSubmission, (await stat(credentialFile)).mode & 0o777, result.disposed], [0o600, 0o600, 1]);
  const key = (await readFile(credentialFile, "utf8")).trimEnd();
  assert.match(key, KEY);
  const { principal } = await (await auth(db, { operation: "lookup", keyPrefix: key.slice(0, 34) })).json();
  assert.deepEqual([principal.id, principal.scopes, principal.revokedAt], ["integration:omni", ["chat", "models"], null]);
  const [, salt, digest] = principal.keyHash.split("$");
  assert.equal(await hashIntegrationKey(key, salt), principal.keyHash);
  const stored = await db.prepare("SELECT COUNT(*) AS n FROM intelligence_credentials WHERE key_prefix = ? OR key_hash = ?").bind(key, key).first();
  assert.equal(stored.n, 0);
  for (const secret of [key, key.slice(18, 34), salt, digest]) assert.ok(!(result.stdout + result.stderr).includes(secret));
});

test("duplicate and revoked principals are refused without replacing stored credentials", async (t) => {
  const directory = await workspace(t);
  const db = await database(t);
  assert.equal((await run(provision(join(directory, "first.key"), "integration:omni", "chat"), { db })).code, 0);
  const before = (await db.prepare("SELECT * FROM intelligence_credentials").all()).results;
  const duplicate = await run(provision(join(directory, "second.key"), "integration:omni", "audio"), { db });
  assert.deepEqual([duplicate.code, duplicate.json.error], [1, "credential_conflict"]);
  assert.equal((await stat(join(directory, "second.key"))).mode & 0o777, 0o600);
  assert.equal((await auth(db, { operation: "revoke", principalId: "integration:omni", expectedVersion: 1 })).status, 200);
  const revoked = await run(provision(join(directory, "third.key"), "integration:omni", "chat"), { db });
  assert.deepEqual([revoked.code, revoked.json.error], [1, "credential_conflict"]);
  assert.deepEqual((await db.prepare("SELECT * FROM intelligence_credentials").all()).results, before);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM intelligence_principals").first()).n, 1);
});

test("existing, linked and racing credential targets are never followed or replaced", async (t) => {
  const directory = await workspace(t);
  const existing = join(directory, "existing.key");
  const linked = join(directory, "linked.key");
  const dangling = join(directory, "dangling.key");
  const throughLink = join(directory, "created-through-link");
  await writeFile(existing, "keep\n");
  await symlink(existing, linked);
  await symlink(throughLink, dangling);
  for (const [file, error] of [
    [existing, "credential_target_exists"], [linked, "credential_target_exists"],
    [dangling, "credential_target_exists"], [join(directory, "missing", "omni.key"), "credential_target_invalid"],
  ]) {
    const result = await run(provision(file));
    assert.deepEqual([result.json.error, result.opened], [error, 0]);
  }
  // A link planted after the preflight check is still refused by the exclusive create.
  const racing = join(directory, "racing.key");
  let touched = false;
  const refuse = () => { touched = true; throw new Error("must not submit"); };
  const raced = await run(provision(racing), {
    open: async () => { await symlink(throughLink, racing); return { prepare: refuse, batch: refuse }; },
  });
  assert.deepEqual([raced.json.error, touched, raced.disposed], ["credential_target_exists", false, 1]);
  assert.equal(await readFile(existing, "utf8"), "keep\n");
  await assert.rejects(lstat(throughLink), { code: "ENOENT" });
});

test("uncertain submissions keep the saved key, are never replayed and stay sanitized", async (t) => {
  const directory = await workspace(t);
  let submissions = 0;
  const failing = {
    prepare: () => ({ bind: () => ({ run: async () => { submissions += 1; throw new Error("SENSITIVE detail"); } }) }),
    async batch() { submissions += 1; throw new Error("SENSITIVE detail"); },
  };
  const credentialFile = join(directory, "omni.key");
  const provisioned = await run(provision(credentialFile), { db: failing });
  assert.deepEqual([provisioned.code, provisioned.json.error, submissions], [3, "outcome_uncertain", 1]);
  assert.match((await readFile(credentialFile, "utf8")).trimEnd(), KEY);
  const policyFile = join(directory, "policy.json");
  await writeFile(policyFile, JSON.stringify(policy()));
  const seeded = await run(["seed", ...TARGET, "--apply", "--policy-file", policyFile], { db: failing });
  assert.deepEqual([seeded.code, seeded.json.error, submissions], [3, "outcome_uncertain", 2]);
  const unopened = await run(provision(join(directory, "next.key")), { open: async () => { throw new Error("SENSITIVE token"); } });
  assert.deepEqual([unopened.code, unopened.json.error], [1, "remote_unavailable"]);
  await assert.rejects(lstat(join(directory, "next.key")), { code: "ENOENT" });
  for (const result of [provisioned, seeded, unopened]) assert.doesNotMatch(result.stderr, /SENSITIVE|mllm_|scrypt/);
});

test("seed is insert-only and status reports configuration and row counts only", async (t) => {
  const directory = await workspace(t);
  const db = await database(t);
  const status = async () => (await run(["status", ...TARGET], { db })).json;
  const rows = (count) => ({ policy: count, reservations: 0, principals: 0, credentials: 0 });
  assert.deepEqual(await status(), { version: 1, operation: "status", ok: true, policy: "unseeded", rows: rows(0) });
  const [first, second] = [join(directory, "first.json"), join(directory, "second.json")];
  await writeFile(first, JSON.stringify(policy({ global_daily_tokens: 1234567 })));
  await writeFile(second, JSON.stringify(policy({ global_daily_tokens: 7654321 })));
  const seed = (file) => run(["seed", ...TARGET, "--apply", "--policy-file", file], { db });
  assert.deepEqual((await seed(first)).json, { version: 1, operation: "seed", ok: true, applied: true, inserted: true });
  const repeated = await seed(second);
  assert.equal(repeated.json.inserted, false);
  const stored = await db.prepare("SELECT document FROM intelligence_policy").first();
  assert.equal(JSON.parse(stored.document).global_daily_tokens, 1234567);
  const configured = await run(["status", ...TARGET], { db });
  assert.deepEqual(configured.json, { version: 1, operation: "status", ok: true, policy: "configured", rows: rows(1) });
  assert.doesNotMatch(configured.stdout + repeated.stdout, /1234567|7654321|global_daily_tokens/);
  await db.prepare("UPDATE intelligence_policy SET document = ?").bind(JSON.stringify({ version: 2 })).run();
  assert.equal((await status()).policy, "invalid");
});

test("remote sessions use an isolated D1-only Wrangler config and always clean up", async () => {
  const target = { accountId: ACCOUNT_ID, databaseId: DATABASE_ID };
  const binding = { prepare() {}, batch() {} };
  const seen = [];
  let disposed = 0;
  const proxy = (env, error) => async () => async (options) => {
    seen.push({
      options, config: JSON.parse(await readFile(options.configPath, "utf8")),
      mode: (await stat(options.configPath)).mode & 0o777,
    });
    if (error) throw error;
    return { env, dispose: async () => { disposed += 1; } };
  };
  const session = await openRemoteDatabase(target, proxy({ INTELLIGENCE_DB: binding, OTHER: binding }));
  assert.equal(session.db, binding);
  assert.deepEqual(seen[0].config, {
    name: "multillm-intelligence-operator", compatibility_date: "2026-07-30", account_id: ACCOUNT_ID,
    d1_databases: [{ binding: "INTELLIGENCE_DB", database_id: DATABASE_ID, remote: true }],
  });
  assert.deepEqual({ ...seen[0].options, configPath: "" }, { configPath: "", envFiles: [], persist: false, remoteBindings: true });
  assert.equal(seen[0].mode, 0o600);
  await lstat(seen[0].options.configPath);
  await session.dispose();
  assert.equal(disposed, 1);
  await assert.rejects(openRemoteDatabase(target, proxy({})), { code: "remote_unavailable" });
  assert.equal(disposed, 2);
  await assert.rejects(openRemoteDatabase(target, proxy(null, new Error("start failed"))), /start failed/);
  for (const { options } of seen) await assert.rejects(lstat(dirname(options.configPath)), { code: "ENOENT" });
  await lstat(tmpdir());
});
