import assert from "node:assert/strict";
import test from "node:test";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { handleUsageLedgerRequest, latencyBucket, LATENCY_BUCKETS, validRow } from "../worker/usage-ledger-d1.mjs";
import { applyMigrations } from "./d1_migrations.mjs";

const row = (changes = {}) => ({
  at: "2026-09-26T10:00:00.000Z", principal: "alice", key_prefix: "mllm_abcdefgh", kind: "chat",
  endpoint: "/v1/chat/completions", requested_model: "auto:chat", selected_model: "openai:gpt-4.1",
  status: 200, latency_ms: 300, input_tokens: 100, output_tokens: 20, cost_usd: 0.002, cost_basis: "usage",
  request_id: "req_1", ...changes,
});
const batch = character => character.repeat(32);

async function database(t, extra = {}) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response('ok')}}",
    d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db);
  const env = { INTELLIGENCE_DB: db, ...extra };
  const call = async body => {
    const response = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/usage", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), env);
    return { status: response.status, body: await response.json() };
  };
  return { db, call };
}

test("a flush stores raw rows and daily totals once, even when the batch is retried", async t => {
  const { db, call } = await database(t);
  const rows = [row(), row({ latency_ms: 5000, status: 502, cost_usd: null, cost_basis: null, input_tokens: null, output_tokens: null }),
    row({ principal: "bob", kind: "images", selected_model: null, requested_model: "auto:image", cost_usd: 0.04, latency_ms: 125000 }),
    row({ at: "2026-09-25T23:59:59.999Z" })];
  assert.deepEqual((await call({ operation: "record", batch: batch("a"), rows })).body, { version: 1, recorded: 4, duplicate: false });
  assert.deepEqual((await call({ operation: "record", batch: batch("a"), rows })).body, { version: 1, recorded: 0, duplicate: true },
    "a retried flush whose reply was lost is not counted twice");
  assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM usage_events").first()).count, 4);
  const daily = await db.prepare("SELECT * FROM usage_daily WHERE day = '2026-09-26' AND principal = 'alice'").first();
  assert.equal(daily.model, "openai:gpt-4.1");
  assert.deepEqual([daily.requests, daily.errors, daily.input_tokens, daily.output_tokens, daily.priced_requests], [2, 1, 100, 20, 1]);
  assert.equal(daily.cost_usd, 0.002);
  assert.equal(daily.lat_le_500, 1);
  assert.equal(daily.lat_le_8000, 1);
  assert.equal((await db.prepare("SELECT model, lat_gt_120000 FROM usage_daily WHERE principal = 'bob'").first()).model, "auto:image",
    "the requested model stands in when none was selected");

  const totals = (await call({ operation: "totals", principal: "alice", day: "2026-09-26", month_start: "2026-09-01" })).body.totals;
  assert.deepEqual(totals, { day_usd: 0.002, month_usd: 0.004, day_requests: 2, month_requests: 3 });

  const byModel = (await call({ operation: "summary", group: "model", since: "2026-09-01", until: "2026-09-30", principal: null, limit: 10 })).body.rows;
  assert.deepEqual(byModel.map(item => item.model), ["auto:image", "openai:gpt-4.1"]);
  assert.equal(byModel[1].requests, 3);
  assert.equal(byModel[1].latency_buckets.length, LATENCY_BUCKETS.length + 1);
  const byDay = (await call({ operation: "summary", group: "day", since: "2026-09-01", until: "2026-09-30", principal: "alice", limit: 10 })).body.rows;
  assert.deepEqual(byDay.map(item => [item.day, item.requests]), [["2026-09-26", 2], ["2026-09-25", 1]]);
  const byPrincipal = (await call({ operation: "summary", group: "principal", since: "2026-09-26", until: "2026-09-26", principal: null, limit: 10 })).body.rows;
  assert.deepEqual(byPrincipal.map(item => item.principal), ["bob", "alice"]);

  const recent = (await call({ operation: "recent", since: "2026-09-26T00:00:00.000Z", principal: "alice", before: null, limit: 1 })).body.rows;
  assert.equal(recent.length, 1);
  assert.equal(recent[0].status, 502);
  const older = (await call({ operation: "recent", since: "2026-09-01T00:00:00.000Z", principal: null, before: recent[0].id, limit: 10 })).body.rows;
  assert.deepEqual(older.map(item => [item.principal, item.status]), [["alice", 200]]);
  assert.deepEqual(Object.keys(recent[0]).sort(), ["at", "cost_basis", "cost_usd", "endpoint", "id", "input_tokens", "key_prefix", "kind",
    "latency_ms", "output_tokens", "principal", "request_id", "requested_model", "selected_model", "status"]);

  const pruned = (await call({ operation: "prune", events_before: "2026-09-26T00:00:00.000Z", rollups_before: "2026-09-26", limit: 100 })).body;
  assert.deepEqual(pruned.pruned, { events: 1, batches: 0, rollups: 1 });
  assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM usage_events").first()).count, 3);
});

test("rows and operations are validated before any statement runs", async t => {
  const { db, call } = await database(t);
  for (const body of [
    { operation: "record", batch: batch("b"), rows: [] },
    { operation: "record", batch: "short", rows: [row()] },
    { operation: "record", batch: batch("b"), rows: [{ ...row(), prompt: "secret" }] },
    { operation: "record", batch: batch("b"), rows: [row({ at: "2026-09-26 10:00:00" })] },
    { operation: "record", batch: batch("b"), rows: [row({ at: "2026-09-26T10:00:00+02:00" })] },
    { operation: "record", batch: batch("b"), rows: [row({ kind: "knowledge" })] },
    { operation: "record", batch: batch("b"), rows: [row({ status: 99 })] },
    { operation: "record", batch: batch("b"), rows: [row({ cost_usd: -1 })] },
    { operation: "record", batch: batch("b"), rows: [row({ cost_basis: "guess" })] },
    { operation: "record", batch: batch("b"), rows: [row({ endpoint: "/v1/chat?key=x" })] },
    { operation: "record", batch: batch("b"), rows: [row({ selected_model: "bad model" })] },
    { operation: "record", batch: batch("b"), rows: [row({ principal: "ali\nce" })] },
    { operation: "record", batch: batch("b"), rows: Array.from({ length: 501 }, () => row()) },
    { operation: "totals", principal: "alice", day: "2026-09-01", month_start: "2026-09-26" },
    { operation: "summary", group: "principal; DROP TABLE usage_events", since: "2026-09-01", until: "2026-09-30", principal: null, limit: 5 },
    { operation: "summary", group: "day", since: "2026-09-01", until: "2026-09-30", principal: null, limit: 501 },
    { operation: "recent", since: "2026-09-01T00:00:00.000Z", principal: null, before: 0, limit: 5 },
    { operation: "prune", events_before: "2026-09-01T00:00:00.000Z", rollups_before: "2026-09-01", limit: 5001 },
    { operation: "sql", statement: "SELECT * FROM usage_events" },
  ]) assert.equal((await call(body)).status, 400, JSON.stringify(body).slice(0, 100));
  assert.equal((await db.prepare("SELECT COUNT(*) AS count FROM usage_batches").first()).count, 0);
  assert.equal(validRow(row()), true);
  assert.deepEqual([0, 250, 251, 120000, 120001].map(latencyBucket), [0, 0, 1, 9, 10]);
});

test("the usage RPC is private, bounded and never reveals storage errors", async () => {
  const env = { INTELLIGENCE_DB: { prepare() { throw new Error("private database detail"); }, batch() { throw new Error("private database detail"); } } };
  const request = (url, body = "{}", headers = { "content-type": "application/json" }) => new Request(url, { method: "POST", headers, body });
  for (const url of ["https://intelligence.internal/v1/usage", "http://other.internal/v1/usage", "http://intelligence.internal/v1/usage?x=1"]) {
    assert.equal((await handleUsageLedgerRequest(request(url), env)).status, 404);
  }
  assert.equal((await handleUsageLedgerRequest(request("http://intelligence.internal/v1/usage", "{}", {}), env)).status, 400);
  assert.equal((await handleUsageLedgerRequest(request("http://intelligence.internal/v1/usage", "x".repeat(300000)), env)).status, 400);
  assert.equal((await handleUsageLedgerRequest(request("http://intelligence.internal/v1/usage"), {})).status, 503);
  const failed = await handleUsageLedgerRequest(request("http://intelligence.internal/v1/usage",
    JSON.stringify({ version: 1, operation: "record", batch: batch("c"), rows: [row()] })), env);
  assert.equal(failed.status, 503);
  assert.equal((await failed.text()).includes("private database detail"), false);
});

test("an optional Analytics Engine binding mirrors stored rows without keys", async t => {
  const points = [];
  const { call } = await database(t, { USAGE_ANALYTICS: { writeDataPoint: point => points.push(point) } });
  await call({ operation: "record", batch: batch("d"), rows: [row(), row({ principal: "bob" })] });
  await call({ operation: "record", batch: batch("d"), rows: [row(), row({ principal: "bob" })] });
  assert.equal(points.length, 2, "a duplicate batch writes nothing");
  assert.deepEqual(points[0].indexes, ["alice"]);
  assert.deepEqual(points[0].doubles, [200, 300, 100, 20, 0.002]);
  assert.equal(JSON.stringify(points).includes("mllm_abcdefgh"), false);
});
