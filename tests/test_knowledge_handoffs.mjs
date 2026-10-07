import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HandoffStore, HANDOFF_PROJECT_LIMIT, HANDOFF_PRINCIPAL_LIMIT } from "../worker/knowledge/handoff-store.mjs";
import { handoffBytes, parseHandoff, renderHandoff, HANDOFF_RENDER_BYTES } from "../worker/knowledge/handoff-contracts.mjs";
import { dispatchKnowledge } from "../worker/knowledge/service.mjs";

const payload = (extra = {}) => ({ project: "synthetic/repo", branch: "feature", title: "Continue synthetic work",
  sections: { goal: "Ship a fixture", state: "Tests pass", files: [{ path: "src/demo.py", change: "Added fixture" }],
    next_steps: ["Review fixture"] }, source: { agent: "codex", thread_id: "synthetic-thread" }, ...extra });
const principal = { id: "synthetic-reader", scopes: ["knowledge:read"] };
function store(t, limits) {
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  const storage = { sql: { exec: (query, ...args) => db.prepare(query).all(...args) }, transactionSync(fn) {
    db.exec("BEGIN"); try { const result = fn(); db.exec("COMMIT"); return result; } catch (error) { db.exec("ROLLBACK"); throw error; }
  } };
  return new HandoffStore(storage, limits);
}
function env(t) {
  const stores = new Map();
  return { stores, KNOWLEDGE_HANDOFFS: { idFromName: name => name, get(name) {
    if (!stores.has(name)) stores.set(name, store(t));
    return { async fetch(_url, init) {
      const { operation, payload: body } = JSON.parse(init.body);
      try { return Response.json({ version: 1, result: stores.get(name).call(operation, body) }); }
      catch (error) { return Response.json({ version: 1, error: { code: error.code, message: error.message } }, { status: error.status }); }
    } };
  } } };
}
const submit = (e, operation, body, identity = principal) => dispatchKnowledge(e,
  { version: 1, principal: identity, operation: "handoffs." + operation, payload: body });

test("handoff save/get/list/delete and exact branch selection with project fallback", t => {
  const s = store(t), now = Date.parse("2026-10-07T00:00:00Z");
  const first = s.call("save", payload(), now);
  const second = s.call("save", payload({ branch: "main" }), now);
  assert.equal(first.trust, "operator");
  assert.equal(first.expires_at, "2026-10-21T00:00:00.000Z");
  assert.equal(s.call("get", { project: "synthetic/repo", branch: "feature" }, now).record.id, first.id);
  for (const body of [{ project: "synthetic/repo", branch: "unknown" }, { project: "synthetic/repo" }]) {
    assert.equal(s.call("get", body, now).record.id, second.id);
  }
  assert.equal(s.call("get", { project: "synthetic/repo", id: first.id, branch: "main" }, now).record.id, first.id);
  assert.equal(s.call("get", { project: "other", id: first.id }, now).record, null);
  assert.deepEqual(s.call("list", { project: "synthetic/repo", limit: 1 }, now).handoffs.map(item => item.id), [second.id]);
  assert.equal(s.call("list", {}, now).handoffs[0].source.thread_id, undefined);
  assert.equal(s.call("delete", { id: first.id }, now).deleted, true);
  assert.equal(s.call("delete", { id: first.id }, now).deleted, false);
});

test("expired handoffs are unreadable at the exact TTL boundary and cleaned on save", t => {
  const s = store(t), now = Date.now();
  const saved = s.call("save", payload({ ttl_days: 1 }), now);
  assert.ok(s.call("get", { project: "synthetic/repo", id: saved.id }, now + 86400000 - 1).record);
  assert.equal(s.call("get", { project: "synthetic/repo" }, now + 86400000).record, null);
  assert.deepEqual(s.call("list", {}, now + 86400000).handoffs, []);
  s.call("save", payload({ ttl_days: 90 }), now + 86400000);
  assert.equal(s.rows("SELECT COUNT(*) AS count FROM handoffs")[0].count, 1);
});

test("transactional oldest-first eviction enforces project and principal defaults", t => {
  const s = store(t), now = Date.now();
  assert.equal(HANDOFF_PROJECT_LIMIT, 50); assert.equal(HANDOFF_PRINCIPAL_LIMIT, 500);
  const oldest = s.call("save", payload(), now).id;
  for (let i = 0; i < 50; i++) s.call("save", payload(), now);
  assert.equal(s.call("get", { project: "synthetic/repo", id: oldest }, now).record, null);
  assert.equal(s.rows("SELECT COUNT(*) AS count FROM handoffs")[0].count, 50);
  const nextOldest = s.call("get", { project: "synthetic/repo" }, now).record.id;
  for (let i = 0; i < 500; i++) s.call("save", payload({ project: `synthetic/${i}` }), now);
  assert.equal(s.rows("SELECT COUNT(*) AS count FROM handoffs")[0].count, 500);
  assert.equal(s.call("get", { project: "synthetic/repo", id: nextOldest }, now).record, null);
});

test("strict handoff validation bounds strings, nested items, arrays, TTL and record bytes", t => {
  const s = store(t);
  const invalid = [{ project: "" }, { project: "x".repeat(201) }, { title: "x".repeat(201) },
    { branch: "x".repeat(201) }, { summary: "x".repeat(4001) }, { extra: true }, { sections: null }, { branch: null }, { summary: null }, { ttl_days: null },
    { sections: { goal: null } }, { sections: { files: null } },
    { source: { agent: "unknown" } }, { source: { agent: "codex", thread_id: "x".repeat(201) } },
    ...[0, 91, 1.5, true, "14"].map(ttl_days => ({ ttl_days })),
    { sections: { goal: "x".repeat(501) } }, { sections: { state: 1 } },
    { sections: { commands: [{ command: "test" }] } },
    { sections: { unknown: [] } }, { sections: { decisions: [false] } }];
  for (const [name, count] of Object.entries({ files: 100, commands: 30, decisions: 30, failed_attempts: 30, next_steps: 30, open_questions: 20 })) {
    invalid.push({ sections: { [name]: Array(count + 1).fill("fixture") } });
  }
  for (const extra of invalid) assert.throws(() => s.call("save", payload(extra)), { code: "invalid_request" });
  assert.throws(() => s.call("save", payload({ sections: { files: Array(100).fill({ path: "x".repeat(500), change: "y".repeat(500) }) } })), /32 KB/);
  assert.equal(s.call("list", {}).handoffs.length, 0);
  for (const body of [{ limit: 0 }, { limit: 21 }, { limit: true }, { project: "" }, { extra: 1 }]) assert.throws(() => parseHandoff("list", body));
  for (const body of [{}, { project: "p", id: "bad/id" }, { project: "p", branch: 1 }]) assert.throws(() => parseHandoff("get", body));
  const saved = s.call("save", payload({ project: "🧭".repeat(200), sections: { goal: "a\nb" } }));
  assert.ok(saved.id);
  assert.ok(s.call("save", payload({ title: "", sections: { files: [{ path: "", change: "" }], commands: [{ command: "", outcome: "" }] } })).id);
});

test("rendering uses the retrieval UTF-8 token estimate and preserves the full structured record", t => {
  const s = store(t);
  s.call("save", payload({ summary: "🧭".repeat(4000), sections: { next_steps: Array(30).fill("Next".repeat(100)) } }));
  const result = s.call("get", { project: "synthetic/repo" });
  assert.ok(new TextEncoder().encode(result.markdown).length <= HANDOFF_RENDER_BYTES);
  assert.ok(!result.markdown.includes("�"));
  assert.equal(result.record.summary.length, 8000);
  assert.ok(handoffBytes(result.record) <= 32768);
  assert.equal(renderHandoff(result.record), result.markdown);
});

test("private dispatch is read scoped, principal isolated, independent of retrieval bindings", async t => {
  const e = env(t);
  const saved = await submit(e, "save", payload());
  assert.equal((await submit(e, "get", { project: "synthetic/repo" })).record.id, saved.id);
  const other = { ...principal, id: "synthetic-other" };
  assert.equal((await submit(e, "get", { project: "synthetic/repo", id: saved.id }, other)).record, null);
  assert.deepEqual((await submit(e, "list", {}, other)).handoffs, []);
  assert.equal((await submit(e, "delete", { id: saved.id }, other)).deleted, false);
  assert.ok((await submit(e, "get", { project: "synthetic/repo" })).record);
  for (const operation of ["save", "get", "list", "delete"]) await assert.rejects(submit(e, operation, {}, { id: "manager", scopes: ["knowledge:manage"] }), { code: "insufficient_scope" });
});

test("existing Knowledge firewall rejects a handoff secret before storage with safe findings", async t => {
  const e = env(t), secret = "AK" + "IA" + "AB12CD34EF56GH78";
  await assert.rejects(submit(e, "save", payload({ sections: { goal: secret } })), error => error.code === "secret_detected" && error.status === 422 && !error.message.includes(secret));
  assert.equal(e.stores.size, 0);
});

test("binding absence, backend refusal and deadlines produce safe feature errors", async () => {
  await assert.rejects(submit({}, "list", {}), { code: "handoffs_unavailable", status: 503 });
  const e = { KNOWLEDGE_HANDOFFS: { idFromName: n => n, get: () => ({ fetch: () => new Promise(() => {}) }) } };
  const started = Date.now();
  await assert.rejects(submit(e, "list", {}), { code: "handoffs_unavailable" });
  assert.ok(Date.now() - started < 3000);
  e.KNOWLEDGE_HANDOFFS.get = () => ({ fetch: async () => ({ json: () => new Promise(() => {}) }) });
  await assert.rejects(submit(e, "list", {}), { code: "handoffs_unavailable" });
  e.KNOWLEDGE_HANDOFFS.get = () => ({ fetch: async () => Response.json({ version: 1, error: { code: "invalid_request", message: "Invalid handoff." } }, { status: 400 }) });
  await assert.rejects(submit(e, "list", {}), { code: "invalid_request", status: 400 });
});

test("catalogue scopes, annotations, toolset and appended SQLite migration match the contract", () => {
  const catalogue = JSON.parse(readFileSync(new URL("../worker/knowledge-mcp-catalogue.json", import.meta.url)));
  const entries = catalogue.tools.filter(item => item.toolset === "handoff");
  assert.equal(entries.length, 4);
  for (const entry of entries) {
    assert.equal(entry.scope, "knowledge:read");
    assert.equal(entry.definition.annotations.readOnlyHint, ["handoffs.get", "handoffs.list"].includes(entry.operation));
  }
  const config = JSON.parse(readFileSync(new URL("../wrangler.knowledge.jsonc", import.meta.url)));
  assert.deepEqual(config.migrations.at(-1), { tag: "add-knowledge-handoffs", new_sqlite_classes: ["KnowledgeHandoffs"] });
  assert.ok(config.durable_objects.bindings.some(item => item.name === "KNOWLEDGE_HANDOFFS"));
});

test("real SQLite handoff Durable Objects isolate principals and survive restart", async t => {
  const bundled = await build({ stdin: { resolveDir: process.cwd(), contents: `
    export { KnowledgeHandoffs } from "./worker/knowledge/index.mjs";
    export default { fetch(request, env) { return env.HANDOFFS.get(env.HANDOFFS.idFromName(new URL(request.url).searchParams.get("principal"))).fetch(request); } };
  ` }, bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], write: false });
  const directory = await mkdtemp(join(tmpdir(), "knowledge-handoffs-"));
  const create = () => new Miniflare(convertV4MiniflareOptions({ cf: false, modules: true, compatibilityDate: "2026-07-28",
    script: bundled.outputFiles[0].text, resourcePersistencePath: directory, durableObjects: { HANDOFFS: { className: "KnowledgeHandoffs", useSQLite: true } } }));
  let mf = create();
  t.after(async () => { await mf.dispose(); await rm(directory, { recursive: true, force: true }); });
  const call = async (operation, body, identity = "one") => {
    const response = await mf.dispatchFetch(`http://handoffs.internal/dispatch?principal=${identity}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ operation, payload: body }) });
    assert.equal(response.status, 200); return (await response.json()).result;
  };
  const saved = await call("save", payload());
  await Promise.all(Array.from({ length: 10 }, () => call("save", payload())));
  assert.equal((await call("list", {})).handoffs.length, 11);
  assert.equal((await call("get", { project: "synthetic/repo", id: saved.id }, "two")).record, null);
  await mf.dispose(); mf = create();
  assert.equal((await call("get", { project: "synthetic/repo", id: saved.id })).record.id, saved.id);
});
