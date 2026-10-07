import assert from "node:assert/strict";
import test from "node:test";
import { firewallFetch, protectPayload } from "../worker/secret-firewall.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
const TOKEN = "AK" + "IA" + "AB12CD34EF56GH78";
const worker = (await loadWorkerModule()).default;
for (const mode of ["off", "observe", "redact", "block"]) test(`direct edge provider ${mode}`, async () => {
  const events = [], bodies = [];
  const env = { ADMIN_API_KEY: "synthetic-bootstrap", OPENCODE_GO_API_KEY: "synthetic-upstream", OPENCODE_EDGE_FETCH: "true",
    SECRET_SCAN_DEFAULT: mode, INTELLIGENCE_DB: { prepare() { return { bind(...args) { events.push(args); return { run: async () => ({}) }; } }; } } };
  const original = globalThis.fetch;
  globalThis.fetch = async req => { bodies.push(await req.text()); return Response.json({ choices: [{ message: { content: "ok" } }] }); };
  let response;
  try { response = await worker.fetch(new Request("https://gateway.invalid/opencode/chat/completions", { method: "POST",
    headers: { authorization: "Bearer synthetic-bootstrap", "content-type": "application/json" },
    body: JSON.stringify({ model: "synthetic-model", messages: [{ role: "user", content: TOKEN }] }) }), env); }
  finally { globalThis.fetch = original; }
  assert.equal(response.status, mode === "block" ? 422 : 200);
  assert.equal(bodies.length, mode === "block" ? 0 : 1);
  if (bodies.length) assert.equal(bodies[0].includes(TOKEN), mode !== "redact");
  assert.equal(events.length, mode === "off" ? 0 : 1);
  assert.ok(!JSON.stringify(events).includes(TOKEN));
  assert.ok(!(await response.text()).includes(TOKEN));
  assert.equal(response.headers.get("X-MultiLLM-Secret-Scan"), { redact: "redacted=1; observed=0", observe: "redacted=0; observed=1" }[mode] ?? null);
});
test("per-key override, Knowledge rule, heuristic and audit failure", async () => {
  const payload = { query: TOKEN };
  for (const mode of ["observe", "redact", "block"]) {
    const decision = await protectPayload(payload, {}, { principal: { secret_scan_mode: mode }, knowledge: true });
    assert.equal(decision.blocked.status, 422);
    assert.deepEqual((await decision.blocked.json()).error.types, { aws_access_key: 1 });
  }
  assert.equal((await protectPayload(payload, { SECRET_SCAN_DEFAULT: "block" }, { principal: { secret_scan_mode: "off" }, knowledge: true })).value, payload);
  const logs = [], originalWarn = console.warn;
  console.warn = (...args) => logs.push(args);
  try {
    const decision = await protectPayload({ password: "AbCdEf0123456789" }, { SECRET_SCAN_DEFAULT: "block", INTELLIGENCE_DB: { prepare() { throw new Error(TOKEN); } } });
    assert.equal(decision.blocked, null); assert.equal(decision.header, "redacted=0; observed=1");
  } finally { console.warn = originalWarn; }
  assert.ok(!JSON.stringify(logs).includes(TOKEN));
});
test("multipart text sanitized, binary bytes intact and invalid JSON scanned as text", async () => {
  const binary = Buffer.from([0, 255, 254]);
  const body = Buffer.concat([Buffer.from(`--synthetic\r\nContent-Disposition: form-data; name="prompt"\r\n\r\n${TOKEN}\r\n--synthetic\r\nContent-Disposition: form-data; name="image"; filename="synthetic.bin"\r\n\r\n`), binary, Buffer.from("\r\n--synthetic--\r\n")]);
  let sent;
  const response = await firewallFetch(new Request("https://provider.invalid", { method: "POST", headers: { "content-type": "multipart/form-data; boundary=synthetic" }, body }), {}, {}, async req => { sent = Buffer.from(await req.arrayBuffer()); return Response.json({ ok: true }); });
  assert.equal(response.status, 200); assert.ok(sent.includes(binary)); assert.ok(!sent.includes(TOKEN));
  const blocked = await firewallFetch(new Request("https://provider.invalid", { method: "POST", headers: { "content-type": "application/json" }, body: TOKEN }), { SECRET_SCAN_DEFAULT: "block" }, {}, () => { throw new Error("must not dispatch"); });
  assert.equal(blocked.status, 422);
});
test("Container forwarding leaves scanning to the Container", async () => {
  let body;
  const env = { ADMIN_API_KEY: "synthetic-bootstrap", SECRET_SCAN_DEFAULT: "block", MULTILLM_PROXY_CONTAINER: { getByName() { return { startAndWaitForPorts: async () => {}, fetch: async req => { body = await req.text(); return Response.json({ ok: true }); }, containerFetch: async (input, init) => { const req = input instanceof Request ? input : new Request("http://container" + input, { ...init, duplex: "half" }); body = await req.text(); return Response.json({ ok: true }); } }; } } };
  const response = await worker.fetch(new Request("https://gateway.invalid/v1/chat/completions", { method: "POST", headers: { authorization: "Bearer synthetic-bootstrap", "content-type": "application/json" }, body: JSON.stringify({ messages: [{ content: TOKEN }] }) }), env);
  assert.equal(response.status, 200); assert.ok(body.includes(TOKEN));
});

for (const mode of ["off", "observe", "redact", "block"]) test(`roleplay dispatch ${mode} and deliberate blocks do not fail over`, async () => {
  const { makeRoleplayEnv, handleRoleplayEdgeRequest, roleplayRequest, completionResponse, withGlobalFetch } = await import("./helpers/roleplay_fixture.mjs");
  const fixture = makeRoleplayEnv({ SECRET_SCAN_DEFAULT: mode, NAVYAI_API_KEY: "synthetic-fallback" });
  const bodies = [];
  const response = await withGlobalFetch(async (_url, init) => {
    bodies.push(init.body); return completionResponse(JSON.parse(init.body).model);
  }, () => handleRoleplayEdgeRequest(roleplayRequest({ session_id: "synthetic-firewall", input: TOKEN, stream: false }), fixture.env));
  assert.equal(response.status, mode === "block" ? 422 : 200);
  assert.equal(bodies.length, mode === "block" ? 0 : 1);
  if (bodies.length) assert.equal(bodies[0].includes(TOKEN), mode !== "redact");
  assert.ok(!(await response.text()).includes(TOKEN));
  if (mode === "redact") assert.equal(response.headers.get("X-MultiLLM-Secret-Scan"), "redacted=1; observed=0");
  await fixture.waitForBackgroundWork();
});
test("URL-encoded text fields are inspected after decoding", async () => {
  let sent;
  const body = "prompt=" + [...TOKEN].map(char => "%" + char.charCodeAt(0).toString(16)).join("");
  const response = await firewallFetch(new Request("https://provider.invalid", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body }), {}, {}, async req => {
    sent = new URLSearchParams(await req.text()).get("prompt"); return Response.json({ ok: true });
  });
  assert.equal(response.status, 200); assert.ok(sent.startsWith("[REDACTED:aws_access_key:"));
});

test("roleplay compaction blocks before fallback or local memory recovery", async () => {
  const { makeRoleplayEnv, handleRoleplayEdgeRequest, roleplayRequest, withGlobalFetch } = await import("./helpers/roleplay_fixture.mjs");
  const fixture = makeRoleplayEnv({ SECRET_SCAN_DEFAULT: "block", ROLEPLAY_KEEP_RECENT_MESSAGES: "4", NAVYAI_API_KEY: "synthetic-fallback" });
  let calls = 0;
  const response = await withGlobalFetch(async () => { calls += 1; throw new Error("must not dispatch"); }, () =>
    handleRoleplayEdgeRequest(roleplayRequest({
      session_id: "synthetic-compaction-block", stream: false, memory: { mode: "force" },
      messages: Array.from({ length: 8 }, (_, index) => ({ role: index % 2 ? "assistant" : "user", content: index === 0 ? TOKEN : `event ${index}` })),
    }), fixture.env));
  assert.equal(response.status, 422);
  const body = await response.text();
  assert.ok(body.includes("secret_detected")); assert.ok(!body.includes(TOKEN));
  assert.equal(calls, 0);
  await fixture.waitForBackgroundWork();
});

for (const mode of ["redact", "observe"]) test(`roleplay ${mode} reports findings confined to compaction`, async () => {
  const { makeRoleplayEnv, handleRoleplayEdgeRequest, roleplayRequest, withGlobalFetch, completionResponse } = await import("./helpers/roleplay_fixture.mjs");
  const fixture = makeRoleplayEnv({ SECRET_SCAN_DEFAULT: mode, ROLEPLAY_KEEP_RECENT_MESSAGES: "4" });
  const bodies = [];
  const response = await withGlobalFetch(async (_url, init) => {
    const payload = JSON.parse(init.body); bodies.push(init.body);
    const compacting = payload.messages[0].content.startsWith("You manage continuity");
    return completionResponse(payload.model, compacting ? JSON.stringify({ compact: true, summary: "prior scene", character_facts: [], relationships: [], world_state: [], open_threads: [], tone_style: [] }) : "ok");
  }, () => handleRoleplayEdgeRequest(roleplayRequest({
    session_id: "synthetic-compaction-counts", stream: false, memory: { mode: "force" },
    messages: Array.from({ length: 8 }, (_, index) => ({ role: index % 2 ? "assistant" : "user", content: index === 0 ? TOKEN : `event ${index}` })),
  }), fixture.env));
  assert.equal(response.status, 200); assert.equal(bodies.length, 2);
  assert.equal(bodies[0].includes(TOKEN), mode === "observe"); assert.ok(!bodies[1].includes(TOKEN));
  assert.equal(response.headers.get("X-MultiLLM-Secret-Scan"), mode === "redact" ? "redacted=1; observed=0" : "redacted=0; observed=1");
  await fixture.waitForBackgroundWork();
});
