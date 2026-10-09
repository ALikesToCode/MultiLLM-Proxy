import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { handleLearnedCooldown, MAX_ENTRIES, TTL_SECONDS } from "../worker/learned-cooldown-d1.mjs";

const bucket = "a".repeat(64), credential = "b".repeat(64);
const env = { LEARNED_COOLDOWN_MODE: "apply" };
const entry = (changes = {}) => ({ credential_digest: credential, lower_seconds: 1, upper_seconds: 60,
  trial_seconds: 30, samples: 6, consistent: 0, steps: 1, confident: true, last_kind: "success",
  last_throttle: null, last_observed: 100, floor_until: 0, created_at: 100,
  expires_at: 100 + TTL_SECONDS, revision: 1, ...changes });
const get = (changes = {}) => ({ version: 1, operation: "get", bucket_digest: bucket,
  credential_digest: credential, now: 100, ...changes });
const put = (changes = {}) => ({ ...get(), operation: "put", expected_revision: 0, entry: entry(), ...changes });
function database(migrated = true) {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec("CREATE TABLE old_state (value TEXT); INSERT INTO old_state VALUES ('kept')");
  const migration = readFileSync(new URL("../intelligence-migrations/0031_learned_cooldown.sql", import.meta.url), "utf8");
  if (migrated) { sqlite.exec(migration); sqlite.exec(migration); }
  const execute = (sql, args) => {
    const numbered = /\?[1-9]/.test(sql);
    const statement = sqlite.prepare(sql.replace(/\?(\d+)/g, (_, number) => `$v${number}`));
    const rows = numbered ? statement.all(Object.fromEntries(args.map((value, index) => [`v${index + 1}`, value]))) : statement.all(...args);
    return { results: rows.map(row => ({ ...row })), meta: { changes: sqlite.prepare("SELECT changes() AS n").get().n } };
  };
  const db = { prepare(sql) { return { sql, args: [], bind(...args) { this.args = args; return this; },
    async first() { return execute(sql, this.args).results[0] ?? null; }, async all() { return execute(sql, this.args); },
    async run() { return execute(sql, this.args); } }; },
  async batch(items) {
    sqlite.exec("BEGIN IMMEDIATE");
    try { const result = items.map(item => execute(item.sql, item.args)); sqlite.exec("COMMIT"); return result; }
    catch (error) { sqlite.exec("ROLLBACK"); throw error; }
  } };
  return { db, sqlite };
}
async function rpc(db, body, settings = env) {
  return handleLearnedCooldown(db, body, settings);
}

test("off empty malformed mode leaves storage untouched", async () => {
  let calls = 0;
  const db = { prepare() { calls++; throw Error("storage touched"); } };
  for (const mode of [undefined, "", "off", "invalid"]) {
    const result = await rpc(db, put(), { LEARNED_COOLDOWN_MODE: mode });
    assert.equal(result.status, 404);
  }
  assert.equal(calls, 0);
});

test("opaque entries round trip in apply and shadow without affecting old rows", async () => {
  for (const mode of ["apply", "shadow"]) {
    const { db, sqlite } = database();
    assert.equal((await (await rpc(db, put(), { LEARNED_COOLDOWN_MODE: mode })).json()).stored, true);
    assert.deepEqual((await (await rpc(db, get())).json()).entry, entry());
    assert.equal(sqlite.prepare("SELECT value FROM old_state").get().value, "kept");
    assert.equal(sqlite.prepare("SELECT bucket_digest FROM learned_cooldown").get().bucket_digest, bucket);
    assert.deepEqual((await (await rpc(db, get({ credential_digest: "c".repeat(64) }))).json()).entry, null);
  }
});

test("compare and swap rejects simultaneous stale updates", async () => {
  const { db } = database();
  const saved = await Promise.all([rpc(db, put()), rpc(db, put())]);
  const results = await Promise.all(saved.map(response => response.json()));
  assert.equal(results.filter(result => result.stored).length, 1);
  const updated = put({ expected_revision: 1, entry: entry({ revision: 2, samples: 7, steps: 2 }) });
  assert.equal((await (await rpc(db, updated)).json()).stored, true);
  assert.equal((await (await rpc(db, updated)).json()).stored, false);
});

test("strict fixed operations reject malformed payloads before D1", async () => {
  let calls = 0;
  const db = { prepare() { calls++; throw Error(); } };
  for (const body of [get({ version: 2 }), get({ bucket_digest: "raw-key" }), get({ now: NaN }),
    get({ extra: "private" }), get({ operation: "sql" }), put({ expected_revision: true }),
    put({ entry: entry({ lower_seconds: 0 }) }), put({ entry: entry({ upper_seconds: 3601 }) }),
    put({ entry: entry({ steps: 13 }) }), put({ entry: entry({ consistent: 4 }) }),
    put({ entry: entry({ confident: 1 }) }), put({ entry: entry({ revision: 2 }) }),
    put({ entry: entry({ extra: "key-prefix" }) }), put({ entry: entry({ expires_at: 200 }) }),
    put({ entry: entry({ last_throttle: 101 }) }), put({ entry: entry({ last_kind: "auth" }) })]) {
    assert.equal((await rpc(db, body)).status, 400);
  }
  assert.equal(calls, 0);
});

test("missing table and storage outage return sanitized 503 with one warning", async () => {
  const { db } = database(false);
  const warnings = [], original = console.warn;
  console.warn = (...values) => warnings.push(values.join(" "));
  try {
    for (const body of [get(), put(), get()]) {
      const response = await rpc(db, body);
      assert.equal(response.status, 503);
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert.equal((await response.json()).error.code, "learned_cooldown_storage_unavailable");
    }
    assert.equal(warnings.length, 1);
    assert.doesNotMatch(warnings.join(), /SELECT|sqlite|no such table|synthetic/);
  } finally { console.warn = original; }
});

test("absolute seven day expiry permits a new revision without reviving expired state", async () => {
  const { db, sqlite } = database();
  await rpc(db, put());
  const now = 100 + TTL_SECONDS;
  assert.equal((await (await rpc(db, get({ now }))).json()).entry, null);
  assert.equal((await (await rpc(db, put({ now, entry: entry({ created_at: now, last_observed: now, expires_at: now + TTL_SECONDS }) }))).json()).stored, true);
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM learned_cooldown").get().n, 1);
});

test("global capacity is bounded and expired rows are reclaimed", async () => {
  const { db, sqlite } = database();
  const seed = sqlite.prepare("INSERT INTO learned_cooldown (bucket_digest, credential_digest, lower_seconds, upper_seconds, trial_seconds, samples, consistent, steps, confident, last_kind, last_throttle, last_observed, floor_until, created_at, expires_at, revision) VALUES (?, ?, 1, 60, 30, 6, 0, 1, 1, 'success', NULL, 100, 0, 100, ?, 1)");
  for (let index = 0; index < MAX_ENTRIES; index++) seed.run(index.toString(16).padStart(64, "0"), credential, 100 + TTL_SECONDS);
  assert.equal((await (await rpc(db, put())).json()).stored, false);
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM learned_cooldown").get().n, MAX_ENTRIES);
  const now = 100 + TTL_SECONDS;
  assert.equal((await (await rpc(db, put({ now, entry: entry({ created_at: now, last_observed: now, expires_at: now + TTL_SECONDS }) }))).json()).stored, true);
});

test("corrupt stored bounds never become an applied suggestion", async () => {
  const { db, sqlite } = database();
  await rpc(db, put());
  sqlite.exec("UPDATE learned_cooldown SET last_kind='corrupt'");
  assert.equal((await rpc(db, get())).status, 503);
});
