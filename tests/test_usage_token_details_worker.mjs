import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { createUsageObserver } from "../worker/request-telemetry.mjs";
import { handleUsageLedgerRequest, recordNativeUsage } from "../worker/usage-ledger-d1.mjs";
import { applyMigrations } from "./d1_migrations.mjs";

async function database(t) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true,
    script: "export default {fetch(){return new Response('ok')}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  return { INTELLIGENCE_DB: db };
}

test("reported cache and reasoning tokens persist in atomic D1 rollups", async t => {
  const env = await database(t);
  const observer = createUsageObserver(true);
  for (const usage of [{ prompt_tokens: 100, prompt_tokens_details: { cached_tokens: 60 } },
    { completion_tokens: 20, completion_tokens_details: { reasoning_tokens: 8 } }]) {
    observer.feed(new TextEncoder().encode(`data: ${JSON.stringify({ usage })}\n\n`));
  }
  const { usage } = observer.finish();
  assert.deepEqual(usage, { input_tokens: 100, output_tokens: 20, cached_input_tokens: 60, reasoning_tokens: 8 });
  await recordNativeUsage(env, { ...usage, provider: "openrouter", model: "example/model", principal: "example",
    status: 200, endpoint: "/v1/chat/completions", duration_ms: 5, requestId: "a".repeat(32), cost_usd: null, cost_basis: null });
  const stored = await env.INTELLIGENCE_DB.prepare("SELECT cached_input_tokens, reasoning_tokens FROM usage_events").first();
  assert.deepEqual(stored, { cached_input_tokens: 60, reasoning_tokens: 8 });
  for (const group of ["model", "principal"]) {
    const response = await handleUsageLedgerRequest(new Request("http://intelligence.internal/v1/usage", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, operation: "summary",
        group, since: "2000-01-01", until: "2100-01-01", principal: null, limit: 10 }),
    }), env);
    const [row] = (await response.json()).rows;
    assert.equal(row.cached_input_tokens, 60);
    assert.equal(row.reasoning_tokens, 8);
  }
});
