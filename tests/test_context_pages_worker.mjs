import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import {
  ContextPageStore, TOOL_SCHEMA, pageContextMessages, retrieveContextTool,
  handleContextPageRequest, handleContextPageStateRequest,
} from "../worker/context-pages-d1.mjs";
import { estimateTokens, buildUpstreamPayload, compactionPlan, parseRoleplayPayload, prepareRoleplayContextPages, buildRoleplayMessages } from "../worker/roleplay/memory.mjs";
import { prepareRoleplayPagingCandidates } from "../worker/roleplay/capacity.mjs";

function setup() {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec(readFileSync(new URL("../intelligence-migrations/0024_context_pages.sql", import.meta.url), "utf8"));
  const db = { prepare(sql) {
    const stmt = sqlite.prepare(sql);
    return { bind(...args) { return {
      async first() { return stmt.get(...args) ?? null; },
      async run() { return { success: true, meta: { changes: stmt.run(...args).changes } }; },
    }; } };
  } };
  const objects = new Map();
  const bucket = {
    async put(key, body) { objects.set(key, new Uint8Array(body)); },
    async get(key) { const body = objects.get(key); return body ? { size: body.length,
      async arrayBuffer() { return body.slice().buffer; } } : null; },
    async delete(key) { objects.delete(key); },
  };
  const env = { CONTEXT_PAGING_ENABLED: "true", INTELLIGENCE_DB: db, multillm_media: bucket,
    MEDIA_SIGNING_SECRET: "synthetic-signing-fixture" };
  const scope = { principal: "alice", session: "session", revision: "rev-1" };
  const store = new ContextPageStore(env, { clock: () => 1000 });
  return { sqlite, objects, env, scope, store };
}

const messages = () => [
  { role: "system", content: "Exact directive" },
  { role: "user", content: "old 雪\n".repeat(600) },
  { role: "assistant", content: null, tool_calls: [
    { id: "a", type: "function", function: { name: "read", arguments: "{}" } },
    { id: "b", type: "function", function: { name: "read", arguments: "{}" } },
  ] },
  { role: "tool", tool_call_id: "b", content: "  bytes\n\t雪  " },
  { role: "tool", tool_call_id: "a", content: "answer" },
  { role: "assistant", content: "Done" },
  { role: "user", content: "Current request" },
];
const options = fixture => ({ ...fixture, capabilities: ["multillm_context_retrieve"],
  retentionPolicy: { enabled: false, mode: "inherit" }, managed: true, pageMessages: pageContextMessages,
  inputBudget: 500, estimateTokens });

async function page(fixture, extra = {}) {
  return pageContextMessages({ ...options(fixture), messages: messages(), ...extra });
}

test("exact UTF-8 tool exchange roundtrip, scoped signed handles and no hidden raw blob", async () => {
  const fixture = setup();
  const plan = await page(fixture);
  assert.equal(plan.pages.length, 1);
  assert.deepEqual(plan.messages[0], messages()[0]);
  assert.deepEqual(plan.messages.at(-1), messages().at(-1));
  assert(!JSON.stringify(plan.messages).includes("old 雪"));
  assert.deepEqual(plan.tools, [TOOL_SCHEMA]);
  const restored = await fixture.store.get(fixture.scope, plan.pages[0].page_id);
  assert.deepEqual(restored.messages, messages().slice(1, -1));
  assert.equal(Buffer.from(restored.body_base64, "base64").toString(), JSON.stringify(messages().slice(1, -1)));
  assert([...fixture.objects.keys()].every(key => key.startsWith("context-pages/")));
});

test("default, empty, malformed, raw, incapable and zero retention paths do no storage", async () => {
  for (const extra of [{ env: {} }, { env: { CONTEXT_PAGING_ENABLED: "" } },
    { env: { CONTEXT_PAGING_ENABLED: "invalid" } }, { managed: false },
    { capabilities: [] }, { retentionPolicy: { enabled: true, mode: "zero" } }]) {
    const fixture = setup();
    const source = messages();
    const result = await page(fixture, { messages: source, inputBudget: 1, ...extra });
    assert.equal(result.messages, source);
    assert.equal(fixture.objects.size, 0);
    assert.equal(fixture.sqlite.prepare("SELECT COUNT(*) AS n FROM context_pages").get().n, 0);
  }
});

test("retrieval rejects foreign principals, sessions, revisions, modified handles and expiry", async () => {
  const fixture = setup();
  const plan = await page(fixture);
  const id = plan.pages[0].page_id;
  for (const scope of [{ ...fixture.scope, principal: "bob" }, { ...fixture.scope, session: "other" },
    { ...fixture.scope, revision: "rev-2" }]) {
    await assert.rejects(fixture.store.get(scope, id), error => error.status === 404);
  }
  await assert.rejects(fixture.store.get(fixture.scope, id.slice(0, -1) + "!"), error => error.status === 404);
  fixture.store.clock = () => 4600;
  await assert.rejects(fixture.store.get(fixture.scope, id), error => error.status === 404);
});

test("tampered R2 content fails closed", async () => {
  const fixture = setup();
  const plan = await page(fixture);
  const key = [...fixture.objects.keys()][0];
  fixture.objects.set(key, new TextEncoder().encode("[]"));
  await assert.rejects(fixture.store.get(fixture.scope, plan.pages[0].page_id), error => error.status === 503);
});

test("no-fit and incomplete exchanges fail before R2 writes", async () => {
  for (const change of [value => { value.at(-1).content = "protected".repeat(1000); },
    value => value.splice(4, 1), value => { value[4].tool_call_id = "b"; },
    value => value.splice(3, 0, { role: "developer", content: "Protected exchange" }),
    value => { value[2].function_call = { name: "legacy" }; }]) {
    const fixture = setup();
    const input = messages();
    change(input);
    await assert.rejects(page(fixture, { messages: input }), error => error.status === 413);
    assert.equal(fixture.objects.size, 0);
  }
});

test("page and atomic session byte limits, including competing writers", async () => {
  const fixture = setup();
  await assert.rejects(fixture.store.put(fixture.scope, [new Uint8Array(65537)]), error => error.status === 413);
  const bodies = Array.from({ length: 16 }, () => new TextEncoder().encode('"' + "x".repeat(65534) + '"'));
  const competing = await Promise.allSettled([
    fixture.store.put(fixture.scope, bodies), fixture.store.put(fixture.scope, bodies),
  ]);
  assert.equal(competing.filter(result => result.status === "fulfilled").length, 1);
  assert.equal(competing.find(result => result.status === "rejected").reason.status, 413);
  assert.equal(fixture.sqlite.prepare("SELECT SUM(byte_length) AS n FROM context_pages").get().n, 1048576);
  assert.equal(fixture.objects.size, 16);
});

test("missing table, binding or signing configuration returns real 503 JSON", async () => {
  for (const missing of ["table", "multillm_media", "INTELLIGENCE_DB", "MEDIA_SIGNING_SECRET"]) {
    const fixture = setup();
    if (missing === "table") fixture.sqlite.exec("DROP TABLE context_pages");
    else delete fixture.env[missing];
    const response = await handleContextPageStateRequest(new Request("http://intelligence.internal/v1/managed-state/context-pages", {
      method: "POST", body: JSON.stringify({ operation: "get", scope: fixture.scope, page_id: "cp_" + "a".repeat(32) + "_" + "s".repeat(43),
        retention_policy: { enabled: false, mode: "inherit" }, granted: true }),
    }), fixture.env);
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error.code, "context_paging_unavailable");
    assert.equal(fixture.objects.size, 0);
  }
});

test("registered Worker retrieval resolves current grants and policy on every call", async () => {
  const fixture = setup();
  const plan = await page(fixture);
  const authority = { scope: fixture.scope, granted: true, retentionPolicy: { enabled: false, mode: "inherit" } };
  const request = new Request("https://fixture/v1/context/pages/" + plan.pages[0].page_id);
  let response = await handleContextPageRequest(request, fixture.env, { store: fixture.store, authorize: async () => authority });
  assert.equal(response.status, 200);
  assert.deepEqual((await response.json()).messages, messages().slice(1, -1));
  authority.granted = false;
  response = await handleContextPageRequest(request, fixture.env, { store: fixture.store, authorize: async () => authority });
  assert.equal(response.status, 403);
  authority.granted = true;
  authority.retentionPolicy = { enabled: true, mode: "zero" };
  response = await handleContextPageRequest(request, fixture.env, { store: fixture.store, authorize: async () => authority });
  assert.equal(response.status, 403);
});

test("candidate paging preserves model choice and supplies only the paged upstream view", async () => {
  const fixture = setup();
  const candidates = [{ provider: "opencode", model: "explicit", family: "glm", contextWindow: 650, maxOutputTokens: 100 }];
  const settings = { contextReplyReserveTokens: 100, contextSafetyTokens: 10 };
  const parsed = { stream: false, forwarded: {} };
  const prepared = await prepareRoleplayPagingCandidates(candidates, 100, settings,
    { ...options(fixture), messages: messages() });
  assert.equal(prepared[0].model, "explicit");
  const payload = buildUpstreamPayload(parsed, prepared[0], messages(), settings);
  assert(!JSON.stringify(payload).includes("old 雪"));
  assert.deepEqual(payload.tools, [TOOL_SCHEMA]);
  assert.deepEqual(payload.messages.at(-1), messages().at(-1));
  assert(!JSON.stringify(payload).includes("body_base64"));
});


test("explicit tool retrieval validates schema, grant and retention", async () => {
  const fixture = setup();
  const plan = await page(fixture);
  const authority = { scope: fixture.scope, granted: true, store: fixture.store,
    retentionPolicy: { enabled: false, mode: "inherit" } };
  const retrieved = await retrieveContextTool({ page_id: plan.pages[0].page_id }, authority);
  assert.deepEqual(retrieved.messages, messages().slice(1, -1));
  for (const value of [null, {}, { page_id: plan.pages[0].page_id, principal: "alice" }]) {
    await assert.rejects(retrieveContextTool(value, authority), error => error.status === 400);
  }
  await assert.rejects(retrieveContextTool({ page_id: plan.pages[0].page_id }, { ...authority, granted: false }),
    error => error.status === 403);
});

test("failed R2 writes and D1 writes retain no dispatchable partial pages", async () => {
  for (const failed of ["R2", "D1"]) {
    const fixture = setup();
    if (failed === "R2") fixture.env.multillm_media.put = async () => { throw new Error("fixture failure"); };
    else {
      const oldPrepare = fixture.env.INTELLIGENCE_DB.prepare;
      fixture.env.INTELLIGENCE_DB.prepare = sql => {
        if (sql.includes("INSERT INTO context_pages")) throw new Error("fixture failure");
        return oldPrepare(sql);
      };
    }
    await assert.rejects(page(fixture), error => error.status === 503);
    assert.equal(fixture.objects.size, 0);
    assert.equal(fixture.sqlite.prepare("SELECT COUNT(*) AS n FROM context_pages").get().n, 0);
  }
});

test("missing schema is checked before creating any R2 objects", async () => {
  const fixture = setup();
  fixture.sqlite.exec("DROP TABLE context_pages");
  await assert.rejects(page(fixture), error => error.status === 503);
  assert.equal(fixture.objects.size, 0);
});

test("private put and get preserve bytes and reject zero retention before storing", async () => {
  const fixture = setup();
  const body = Buffer.from(JSON.stringify(messages().slice(1, -1))).toString("base64");
  const call = values => handleContextPageStateRequest(new Request("http://intelligence.internal/v1/managed-state/context-pages", {
    method: "POST", body: JSON.stringify({ scope: fixture.scope, granted: true,
      retention_policy: { enabled: false, mode: "inherit" }, ...values }),
  }), fixture.env);
  let response = await call({ operation: "put", bodies: [body] });
  assert.equal(response.status, 200);
  const id = (await response.json()).pages[0].page_id;
  response = await call({ operation: "get", page_id: id });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).body_base64, body);
  response = await call({ operation: "put", bodies: [body], retention_policy: { enabled: true, mode: "zero" } });
  assert.equal(response.status, 403);
  assert.equal(fixture.objects.size, 1);
});

test("candidate plans reuse page bodies and bypass lossy compaction", async () => {
  const fixture = setup();
  const candidate = { provider: "opencode", model: "explicit", family: "glm", contextWindow: 650, maxOutputTokens: 100 };
  const settings = { contextReplyReserveTokens: 100, contextSafetyTokens: 10,
    hardInputTokens: 650, compactTriggerTokens: 1, maxStoredBytes: 10000, keepRecentMessages: 2 };
  const prepared = await prepareRoleplayPagingCandidates([candidate, { ...candidate, model: "fallback", contextWindow: 600 }],
    100, settings, { ...options(fixture), messages: messages() });
  assert.equal(prepared.length, 2);
  assert.equal(fixture.objects.size, 1);
  const parsed = parseRoleplayPayload({ messages: [{ role: "user", content: "continue" }],
    capabilities: ["multillm_context_retrieve"], memory: { mode: "force" } });
  const state = { directives: [], memory: null };
  const plan = compactionPlan(state, parsed, messages(), settings, prepared[0].contextPlan);
  assert.equal(plan.requested, false);
  assert.deepEqual(plan.roleplayMessages, prepared[0].contextPlan.messages);
  const roleplayPlan = await prepareRoleplayContextPages(state, parsed, messages(),
    { hardInputTokens: estimateTokens(buildRoleplayMessages(state, parsed, messages(), true)) - 100 }, options(fixture));
  assert(roleplayPlan.pages.length > 0);
  const restored = await fixture.store.get(fixture.scope, roleplayPlan.pages[0].page_id);
  assert.deepEqual(restored.messages, messages().slice(1, -1));
});

test("protected-only candidates return 413 and expired pages release the session allowance", async () => {
  const fixture = setup();
  const candidate = { provider: "opencode", model: "explicit", family: "glm", contextWindow: 30, maxOutputTokens: 10 };
  await assert.rejects(prepareRoleplayPagingCandidates([candidate], 10,
    { contextReplyReserveTokens: 10, contextSafetyTokens: 10 }, { ...options(fixture), messages: messages() }),
    error => error.status === 413);
  assert.equal(fixture.objects.size, 0);
  const body = new TextEncoder().encode('"' + "x".repeat(65534) + '"');
  await fixture.store.put(fixture.scope, Array.from({ length: 16 }, () => body));
  fixture.store.clock = () => 4600;
  const result = await fixture.store.put(fixture.scope, [body]);
  assert.equal(result.length, 1);
});
