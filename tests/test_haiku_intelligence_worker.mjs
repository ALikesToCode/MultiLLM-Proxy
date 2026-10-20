import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { applyMigrations } from "./d1_migrations.mjs";

const migrationName = "0039_haiku_primary.sql";
const migration = (await readFile(new URL(`../intelligence-migrations/${migrationName}`, import.meta.url), "utf8"))
  .replace(/^--.*$/gm, "");
const selector = "anthropic:claude-haiku-5-5";
const originalCandidate = {
  model: "openai:fallback", capabilities: ["tools", "json", "reasoning", "streaming"],
  enabled: true, entitled: true, privacy_allowed: true, billing: "allowance",
  context_window: 32768, max_output_tokens: 4096, quality_tier: 5,
};
const policy = (overrides = {}) => ({
  version: 1, enabled: true, allow_paid_overage: false,
  max_attempts: 3, max_escalations: 1, deadline_ms: 45000,
  max_total_tokens: 131072, max_output_tokens: 4096,
  principal_daily_tokens: 1048576, global_daily_tokens: 1048576, max_inflight: 2,
  max_request_bytes: 1048576, max_response_bytes: 4194304,
  candidates: [originalCandidate], media: {}, ...overrides,
});

async function fixture(t, document) {
  const mf = new Miniflare(convertV4MiniflareOptions({
    cf: false, modules: true, script: "export default {fetch(){return new Response('ok')}}",
    d1Databases: ["INTELLIGENCE_DB"],
  }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db, { skip: [migrationName] });
  if (document !== undefined) await db.prepare("INSERT INTO intelligence_policy (id, document) VALUES (1, ?)")
    .bind(typeof document === "string" ? document : JSON.stringify(document)).run();
  return {
    db,
    apply: () => db.batch(migration.split(";").filter(sql => sql.trim()).map(sql => db.prepare(sql))),
    stored: async () => (await db.prepare("SELECT document FROM intelligence_policy WHERE id = 1").first())?.document,
    backup: async () => (await db.prepare("SELECT document FROM shadow_eval_policy_backups WHERE id = 'haiku-primary-20261011'").first())?.document,
  };
}

test("Haiku migration promotes the primary and preserves fallbacks, limits and the original policy", async t => {
  const original = policy({ candidates: [originalCandidate, { ...originalCandidate, model: "navyai:second" }] });
  const f = await fixture(t, original);
  assert.ok((await f.apply()).every(result => result.success));
  const migrated = JSON.parse(await f.stored());
  assert.equal(migrated.candidates[0].model, selector);
  assert.equal(migrated.candidates[0].billing, "payg");
  assert.equal(migrated.candidates[0].context_window, 1000000);
  assert.equal(migrated.candidates[0].max_output_tokens, 128000);
  assert.deepEqual(migrated.candidates.slice(1), original.candidates);
  const { candidates, allow_paid_overage, ...unchanged } = migrated;
  assert.equal(allow_paid_overage, true);
  const { candidates: previousCandidates, allow_paid_overage: previousPaid, ...previous } = original;
  assert.deepEqual(unchanged, previous);
  assert.equal(await f.backup(), JSON.stringify(original));
  const stored = await f.stored();
  await f.apply();
  assert.equal(await f.stored(), stored, "reapplying does not create another primary");
  assert.equal(await f.backup(), JSON.stringify(original), "reapplying keeps the first backup");
});

test("an existing Haiku candidate keeps its eligibility and capability decisions", async t => {
  const existing = { ...originalCandidate, model: selector, enabled: false, entitled: false,
    privacy_allowed: false, billing: "payg", capabilities: ["streaming"], max_output_tokens: 128 };
  const original = policy({ candidates: [originalCandidate, existing] });
  const f = await fixture(t, original);
  await f.apply();
  assert.deepEqual(JSON.parse(await f.stored()).candidates, [existing, originalCandidate]);
});

test("disabled, invalid, unsupported and unseeded policies stay unchanged", async t => {
  for (const original of [undefined, "null", policy({ enabled: false }),
    policy({ version: 2 }), policy({ candidates: null }),
    policy({ candidates: ["invalid-candidate"] }), policy({ candidates: [{}] })]) {
    await t.test(String(original?.enabled ?? original), async child => {
      const f = await fixture(child, original);
      const before = await f.stored();
      await f.apply();
      assert.equal(await f.stored(), before);
      assert.equal(await f.backup(), undefined);
    });
  }
});

test("the schema rejects malformed JSON before a policy can be stored", async t => {
  const f = await fixture(t);
  await assert.rejects(
    f.db.prepare("INSERT INTO intelligence_policy (id, document) VALUES (1, ?)").bind("not-json").run(),
    /CHECK constraint failed: json_valid\(document\)/,
  );
  assert.equal(await f.stored(), undefined);
});

test("a full candidate list is left intact unless Haiku is already present", async t => {
  const candidates = Array.from({ length: 64 }, (_, index) => ({ ...originalCandidate, model: `openai:model-${index}` }));
  const f = await fixture(t, policy({ candidates }));
  const before = await f.stored();
  await f.apply();
  assert.equal(await f.stored(), before);
  assert.equal(await f.backup(), undefined);
});

test("a concurrent policy edit after backup is preserved", async t => {
  const f = await fixture(t, policy());
  const statements = migration.split(";").filter(sql => sql.trim());
  await f.db.prepare(statements[0]).run();
  const edited = policy({ max_attempts: 2 });
  await f.db.prepare("UPDATE intelligence_policy SET document = ? WHERE id = 1").bind(JSON.stringify(edited)).run();
  await f.db.prepare(statements[1]).run();
  assert.equal(await f.stored(), JSON.stringify(edited));
  assert.equal(await f.backup(), JSON.stringify(policy()));
});
