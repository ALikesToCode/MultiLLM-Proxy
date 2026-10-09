import assert from "node:assert/strict";
import test from "node:test";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { nativeGenerationFetch } from "../worker/gateway-extensions.mjs";
import { principalHash, admissionModelGroup } from "../worker/admission-do.mjs";
import { nativeRevisionConsumer } from "../worker/native-config-sync.mjs";

const { default: worker, MultiLLMProxyContainer } = await loadWorkerModule();
const baselineWorker = (await loadWorkerModule({ transformSource: source => source
  .replace("import { nativeGenerationFetch,", "import { nativeGenerationFetch as observedNativeGenerationFetch,")
  + "\nfunction nativeGenerationFetch(request, env, ctx, authority, fetcher) { return fetcher(request, env, authority); }\n",
})).default;
const instrumentedWorker = await loadWorkerModule({ transformSource: source => source
  .replace("import { nativeGenerationFetch,", "import { nativeGenerationFetch as observedNativeGenerationFetch,") + `
export const hubEvents = [], hubContexts = [], hubOutcomes = [];
function nativeGenerationFetch(request, env, ctx, authority, fetcher) {
  return observedNativeGenerationFetch(request, env, ctx, { ...authority,
    onCancellationOutcome: outcome => hubOutcomes.push(outcome) }, (...args) => {
      hubEvents.push("dispatch"); return fetcher(...args);
    }, [{ enabled: env => env.CONTENT_RETENTION_ENABLED === "true",
      authorize(context) { hubEvents.push("retention"); hubContexts.push(context); },
      before_dispatch() { hubEvents.push("before_dispatch"); },
      observe() { hubEvents.push("observe"); },
      finalize(event) { hubEvents.push("finalize"); hubContexts.push(event); }
    }]);
}
` });
const vector = "a5d35b6466ec3a0d0858b4eb73370c1703f8ccdb68c6586f9d41d1cd0075ddec";
const raw = '{"usage":{"prompt_tokens":2,"completion_tokens":0},"choices":[]}';
const paths = ["/codex-easy/v1/chat/completions", "/linkapi/v1/chat/completions", "/opencode/v1/chat/completions",
  "/codex-easy/v1/images/edits", "/linkapi/v1beta/models/test-model:streamGenerateContent"];
const request = (path = paths[0], options = {}) => new Request(`https://gateway.example${path}`, {
  method: "POST", headers: { authorization: "Bearer synthetic-admin", "content-type": "application/json",
    "x-multillm-principal": "spoofed", "x-request-id": "spoofed", ...options.headers },
  body: JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "private-prompt" }] }), signal: options.signal,
});
const response = () => new Response(raw, { headers: { "content-type": "application/json", "retry-after": "7" } });
function fixture(overrides = {}) {
  const pending = [], operations = [], rows = [];
  const env = { ADMIN_API_KEY: "synthetic-admin", CODEX_EASY_API_KEY: "synthetic-upstream",
    LINKAPI_KEY: "synthetic-link", OPENCODE_GO_API_KEY: "synthetic-open", OPENCODE_EDGE_FETCH: "true", ...overrides };
  env.ADMISSION_COORDINATOR = { getByName() { return { async fetch(req) {
    const body = await req.json(); operations.push(body);
    return Response.json({ version: 1, ...(body.operation === "release" ? { released: true }
      : { lease: { lease_id: "a".repeat(32), expires_at: Math.min(Date.now() + 29000, body.deadline_ms) } }) });
  } }; } };
  env.INTELLIGENCE_DB = { prepare(sql) { return { sql, values: [], bind(...values) { this.values = values; return this; },
    async all() { return { results: [] }; } }; }, async batch(statements) {
    rows.push(...JSON.parse(statements[1].values[0])); return [{ meta: { changes: 1 } }];
  } };
  return { env, operations, rows, ctx: { waitUntil(promise) { pending.push(promise); } },
    async flush() { await Promise.all(pending); } };
}
async function upstream(fetcher, run) {
  const original = globalThis.fetch;
  globalThis.fetch = fetcher;
  try { return await run(); } finally { globalThis.fetch = original; }
}
const snapshot = async res => ({ status: res.status, statusText: res.statusText,
  headers: [...res.headers], body: Buffer.from(await res.arrayBuffer()).toString("hex") });

test("shared admission identity strips the authenticated username", async () => {
  assert.equal(await principalHash("admin"), vector);
  assert.equal(await principalHash(" admin "), vector);
  assert.equal(admissionModelGroup("codex-easy", "test-model"), "codex-easy:test-model");
  assert.equal(admissionModelGroup("codex-easy", ""), "codex-easy:");
  for (const invalid of [null, "invalid model", "x".repeat(256)]) {
    assert.equal(admissionModelGroup("codex-easy", invalid), "codex-easy");
  }
});

test("all opt-in flags off preserve native, forwarded and Prometheus responses", async () => {
  for (const path of paths) {
    const baseline = fixture();
    const expected = await upstream(async () => response(), () => baselineWorker.fetch(request(path), baseline.env, baseline.ctx));
    const off = fixture({ NATIVE_EDGE_METRICS_ENABLED: "false", ADMISSION_ENABLED: "false",
      CONFIG_REVISION_SYNC_ENABLED: "false", CONTENT_RETENTION_ENABLED: "false" });
    const actual = await upstream(async () => response(), () => worker.fetch(request(path), off.env, off.ctx));
    assert.deepEqual(await snapshot(actual), await snapshot(expected));
    await off.flush(); assert.equal(off.operations.length, 0); assert.equal(off.rows.length, 0);
  }
  for (const path of ["/v1/chat/completions", "/v1/metrics/prometheus"]) {
    const sent = [];
    const f = fixture({ PROMETHEUS_ENABLED: "true", MULTILLM_PROXY_CONTAINER: { getByName() { return {
      async fetch(req) { sent.push(await snapshot(new Response(req.body, { headers: req.headers })));
        return new Response("container bytes\n", { status: 200, headers: { "content-type": "text/plain", "x-test": "kept" } }); },
    }; } } });
    const first = await baselineWorker.fetch(request(path), f.env, f.ctx);
    const second = await worker.fetch(request(path), { ...f.env, NATIVE_EDGE_METRICS_ENABLED: "false", ADMISSION_ENABLED: "false",
      CONFIG_REVISION_SYNC_ENABLED: "false", CONTENT_RETENTION_ENABLED: "false" }, f.ctx);
    assert.deepEqual(await snapshot(second), await snapshot(first)); assert.deepEqual(sent[1], sent[0]);
    assert.equal(f.operations.length, 0); assert.equal(f.rows.length, 0);
  }
});

test("admission alone returns real native 429 with Retry-After without upstream dispatch", async () => {
  for (const path of paths) {
    const f = fixture({ ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":1}' });
    f.env.ADMISSION_COORDINATOR = { getByName() { return { async fetch(req) {
      f.operations.push(await req.json()); return Response.json({ version: 1, error: { code: "admission_denied" } },
        { status: 429, headers: { "retry-after": "3" } });
    } }; } };
    const result = await upstream(() => assert.fail("Denied dispatch"), () => worker.fetch(request(path), f.env, f.ctx));
    assert.equal(result.status, 429); assert.equal(result.headers.get("retry-after"), "3");
    assert.equal((await result.json()).error.code, "admission_denied");
    assert.equal(f.operations[0].principal_hash, vector);
    assert.equal(f.operations[0].model_group, `${path.split("/")[1]}:test-model`);
    assert.notEqual(f.operations[0].request_id, "spoofed"); assert.equal(f.rows.length, 0);
    await f.flush();
  }
});

test("admission alone releases exactly once on completion and upstream failure", async () => {
  for (const failure of [false, true]) {
    const f = fixture({ ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":1}' });
    await upstream(async () => { if (failure) throw new Error("transport failure"); return response(); }, async () => {
      if (failure) assert.equal((await worker.fetch(request(), f.env, f.ctx)).status, 502);
      else assert.equal(await (await worker.fetch(request(), f.env, f.ctx)).text(), raw);
    });
    await f.flush(); assert.deepEqual(f.operations.map(op => op.operation), ["acquire", "release"]);
    assert.equal(f.rows.length, 0);
  }
});

test("revision guard alone fails closed and private auto-route dispatch requires its schema", async () => {
  const f = fixture({ CONFIG_REVISION_SYNC_ENABLED: "true" });
  f.env.INTELLIGENCE_DB.prepare = () => { throw new Error("missing schema"); };
  for (const path of paths) {
    const result = await upstream(() => assert.fail("Stale dispatch"), () => worker.fetch(request(path), f.env, f.ctx));
    assert.equal(result.status, 503); assert.equal((await result.json()).error.code, "config_security_stale");
  }
  const privateResult = await MultiLLMProxyContainer.outboundByHost["intelligence.internal"](
    new Request("http://intelligence.internal/v1/auto-routes", { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ version: 1, operation: "list" }) }), f.env);
  assert.equal(privateResult.status, 503);
  assert.equal((await privateResult.json()).error.code, "config_revision_storage_unavailable");
  await f.flush(); assert.equal(f.operations.length, 0); assert.equal(f.rows.length, 0);
});

test("native revision installers are strict and the injectable clock bounds freshness", async () => {
  let now = 100, offline = false;
  const f = fixture({ CONFIG_REVISION_SYNC_ENABLED: "true" });
  const db = f.env.INTELLIGENCE_DB;
  db.prepare = sql => ({ sql, bind() { return this; }, async all() {
    if (offline) throw new Error("offline");
    return { results: [] };
  } });
  db.batch = async statements => {
    if (offline) throw new Error("offline");
    return statements.map(() => ({ results: [{ revision: 0 }] }));
  };
  const consumer = nativeRevisionConsumer(f.env, { clock: () => now, jitter: () => 0 });
  await consumer.tick(); assert.equal(consumer.requireFreshSecurity(), null);
  assert.equal(await (await upstream(async () => response(), () => worker.fetch(request(), f.env, f.ctx))).text(), raw);
  offline = true; now += 6;
  assert.equal((await worker.fetch(request(), f.env, f.ctx)).status, 503);
  await f.flush();
  const invalid = fixture({ CONFIG_REVISION_SYNC_ENABLED: "true" });
  invalid.env.INTELLIGENCE_DB.batch = async statements => statements.map(() => ({ results: [{ revision: 0 }] }));
  invalid.env.INTELLIGENCE_DB.prepare = sql => ({ bind() { return this; }, async all() {
    return { results: sql.includes("control_users") ? [{ username: "missing-controls" }] : [] };
  } });
  const broken = nativeRevisionConsumer(invalid.env);
  await broken.tick(); assert.equal(broken.requireFreshSecurity().status, 503);
});

test("registered revision wrapper advances normal writes without exposing snapshots", async () => {
  const f = fixture({ CONFIG_REVISION_SYNC_ENABLED: "true" }), batches = [];
  f.env.INTELLIGENCE_DB.prepare = sql => ({ sql, bind() { return this; },
    async all() { return { results: [] }; }, async first() { return {}; } });
  f.env.INTELLIGENCE_DB.batch = async statements => {
    batches.push(statements.map(statement => statement.sql));
    return statements.map(() => ({ success: true, meta: { changes: 1 } }));
  };
  const dispatch = body => MultiLLMProxyContainer.outboundByHost["intelligence.internal"](
    new Request("http://intelligence.internal/v1/auto-routes", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, ...body }) }), f.env);
  const saved = await dispatch({ operation: "put", route_id: "auto:test-route", candidates: ["openai:test-model"], updated_at: "2026-10-09T00:00:00Z" });
  assert.equal(saved.status, 200); assert.equal(batches.length, 1);
  assert.equal(batches[0].filter(sql => sql.includes("revision=revision+1")).length, 1);
  assert.ok(batches[0].some(sql => sql.includes("INSERT INTO auto_routes")));
  assert.equal((await dispatch({ operation: "snapshot_list" })).status, 404);
  assert.equal(batches.length, 1);
});

test("abort cleanup works alone and with admission, cancelling upstream once", async () => {
  for (const admission of [false, true]) {
    const f = fixture(admission ? { ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":1}' } : {});
    const client = new AbortController(); let cancelled = 0, upstreamSignal;
    const result = await upstream(async req => {
      upstreamSignal = req.signal;
      return new Response(new ReadableStream({ pull() {}, cancel() { cancelled++; } }), { headers: { "content-type": "text/event-stream" } });
    }, () => worker.fetch(request(paths[0], { signal: client.signal }), f.env, f.ctx));
    const reading = result.text(); client.abort();
    await assert.rejects(reading); await new Promise(resolve => setImmediate(resolve)); await f.flush();
    assert.equal(upstreamSignal.aborted, true); assert.equal(cancelled, 1);
    assert.equal(f.operations.filter(op => op.operation === "release").length, admission ? 1 : 0);
    assert.equal(f.rows.length, 0);
  }
});

test("metrics alone observes native generations; forwarded routes never take edge leases", async () => {
  const f = fixture({ NATIVE_EDGE_METRICS_ENABLED: "true" });
  assert.equal(await (await upstream(async () => response(), () => worker.fetch(request(), f.env, f.ctx))).text(), raw);
  await f.flush(); assert.equal(f.rows.length, 1); assert.equal(f.operations.length, 0);
  const forwarded = fixture({ ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":1}',
    CONFIG_REVISION_SYNC_ENABLED: "true", CONTENT_RETENTION_ENABLED: "true",
    MULTILLM_PROXY_CONTAINER: { getByName() { return { fetch: async () => new Response("forwarded") }; } } });
  assert.equal(await (await worker.fetch(request("/v1/chat/completions"), forwarded.env, forwarded.ctx)).text(), "forwarded");
  assert.equal(forwarded.operations.length, 0);
});

test("all enabled hooks run in order and retention uses verified identity and public path", async () => {
  const { hubEvents: seen, hubOutcomes: outcomes, hubContexts: contexts } = instrumentedWorker;
  seen.length = 0; outcomes.length = 0; contexts.length = 0;
  const f = fixture({ NATIVE_EDGE_METRICS_ENABLED: "true", ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":1}',
    CONFIG_REVISION_SYNC_ENABLED: "true", CONTENT_RETENTION_ENABLED: "true",
    CONTENT_RETENTION_POLICY_JSON: '{"routes":{"/codex-easy/v1/chat/completions":"zero"}}' });
  f.env.INTELLIGENCE_DB.batch = async statements => {
    if (statements[0].sql.includes("revision")) return statements.map(() => ({ results: [{ revision: 0 }] }));
    f.rows.push(...JSON.parse(statements[1].values[0])); return [{ meta: { changes: 1 } }];
  };
  await nativeRevisionConsumer(f.env).tick();
  const original = f.env.ADMISSION_COORDINATOR;
  f.env.ADMISSION_COORDINATOR = { getByName(name) { const stub = original.getByName(name); return { fetch(req) {
    seen.push("admission"); return stub.fetch(req);
  } }; } };
  const result = await upstream(async () => response(), () => instrumentedWorker.default.fetch(request(), f.env, f.ctx));
  assert.equal(await result.text(), raw); await f.flush();
  assert.deepEqual(seen, ["retention", "admission", "before_dispatch", "dispatch", "observe", "admission", "finalize"]);
  assert.equal(outcomes.length, 1); assert.equal(f.rows.length, 1);
  assert.deepEqual(contexts[0].retentionPolicy, { enabled: true, mode: "zero" });
  assert.equal(Object.isFrozen(contexts[0].retentionPolicy), true);
  assert.equal(contexts[1].cancellationOutcome.reason, "complete");
  assert.ok(!JSON.stringify(contexts).includes("private-prompt"));
});

test("retention alone uses the verified username, key digest and caller tightening header", async () => {
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("synthetic-admin"))),
    byte => byte.toString(16).padStart(2, "0")).join("");
  for (const [policy, headers, mode] of [
    [{ keys: { admin: "zero" } }, {}, "zero"],
    [{ keys: { [digest]: "zero" } }, {}, "zero"],
    [{}, { "X-MultiLLM-Retention": "zero" }, "zero"],
    [{ keys: { spoofed: "zero" } }, { "X-MultiLLM-Retention-Key-ID": "spoofed" }, "inherit"],
  ]) {
    const f = fixture({ CONTENT_RETENTION_ENABLED: "true", CONTENT_RETENTION_POLICY_JSON: JSON.stringify(policy), ADMIN_USERNAME: " admin " });
    const contexts = instrumentedWorker.hubContexts; contexts.length = 0;
    const result = await upstream(async () => response(), () => instrumentedWorker.default.fetch(request(paths[0], { headers }), f.env, f.ctx));
    assert.equal(await result.text(), raw); await f.flush();
    assert.equal(contexts[0].retentionPolicy.mode, mode); assert.equal(f.rows.length, 0); assert.equal(f.operations.length, 0);
  }
});

test("authentication and freshness rejections precede retention and admission hooks", async () => {
  const f = fixture({ CONTENT_RETENTION_ENABLED: "true", CONFIG_REVISION_SYNC_ENABLED: "true",
    ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":1}' });
  instrumentedWorker.hubEvents.length = 0;
  f.env.INTELLIGENCE_DB.prepare = () => { throw new Error("offline"); };
  const denied = await instrumentedWorker.default.fetch(request(paths[0], { headers: { authorization: "Bearer wrong" } }), f.env, f.ctx);
  assert.equal(denied.status, 401); assert.equal(instrumentedWorker.hubEvents.length, 0);
  const stale = await instrumentedWorker.default.fetch(request(), f.env, f.ctx);
  assert.equal(stale.status, 503); assert.equal(instrumentedWorker.hubEvents.length, 0);
  assert.equal(f.operations.length, 0); await f.flush();
});

test("a collaborator's gate works independently of native metrics", async () => {
  const f = fixture({ ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":1}' });
  let finalizations = 0;
  const result = await nativeGenerationFetch(request(), f.env, f.ctx, { route: paths[0], provider: "codex-easy", principal: { id: "admin" } },
    async () => response(), [{ flag: "ADMISSION_ENABLED", finalize() { finalizations++; } }, { finalize() { assert.fail("Metrics gate"); } }]);
  assert.equal(await result.text(), raw); await f.flush(); assert.equal(finalizations, 1); assert.equal(f.rows.length, 0);
});

test("a pre-dispatch rejection releases the acquired lease and finalizes once", async () => {
  const f = fixture({ ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":1}' });
  let finalized = 0;
  await assert.rejects(nativeGenerationFetch(request(), f.env, f.ctx,
    { route: paths[0], provider: "codex-easy", principal: { id: "admin" } },
    () => assert.fail("Rejected dispatch"), [{ flag: "ADMISSION_ENABLED",
      before_dispatch() { throw new Error("policy rejection"); }, finalize() { finalized++; } }]), /policy rejection/);
  await f.flush(); assert.equal(finalized, 1); assert.equal(f.rows.length, 0);
  assert.deepEqual(f.operations.map(op => op.operation), ["acquire", "release"]);
});

test("lost admission cancels an upstream body and releases once without waiting for acknowledgement", async () => {
  const f = fixture({ ADMISSION_ENABLED: "true", ADMISSION_LIMITS_JSON: '{"principal":1}' });
  let cancelled = 0, signal;
  f.env.ADMISSION_COORDINATOR = { getByName() { return { async fetch(req) {
    const body = await req.json(); f.operations.push(body);
    return Response.json({ version: 1, ...(body.operation === "release" ? { released: true }
      : { lease: { lease_id: "b".repeat(32), expires_at: Date.now() + 30 } }) });
  } }; } };
  const result = await upstream(async req => { signal = req.signal; return new Response(new ReadableStream({
    pull() {}, cancel() { cancelled++; return new Promise(() => {}); },
  })); }, () => worker.fetch(request(), f.env, f.ctx));
  // The lease timer is unref'ed; a bounded test timer keeps the fake request alive.
  let timer;
  try {
    await assert.rejects(Promise.race([result.text(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Lost lease did not close")), 1000); })]),
      error => error.name === "AbortError" || error.code === "admission_unavailable");
  } finally { clearTimeout(timer); }
  await f.flush(); assert.equal(signal.aborted, true); assert.equal(cancelled, 1);
  assert.deepEqual(f.operations.map(op => op.operation), ["acquire", "release"]);
});
