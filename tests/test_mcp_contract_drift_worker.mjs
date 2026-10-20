import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { canonicalContract, canonicalValue, contractDigest, catalogueDigest, discoveryContract, digestsEnabled, checkContractPin } from "../worker/knowledge/contract-drift.mjs";
import { dispatchNative } from "../worker/knowledge/native.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";
import { generateIntegrationCredential } from "../scripts/intelligence_operator.mjs";
import { fixture, principal } from "./knowledge_fixture.mjs";

const baseline = JSON.parse(await readFile(new URL("../docs/mcp-contract-baseline.json", import.meta.url), "utf8"));
const catalogue = JSON.parse(await readFile(new URL("../worker/knowledge-mcp-catalogue.json", import.meta.url), "utf8"));

test("shared Python/Worker canonical vectors and current catalogue digests", async () => {
  for (const v of baseline.vectors) {
    assert.equal(canonicalContract(v.definition, v.contract_version), v.canonical);
    assert.equal(await contractDigest(v.definition, v.contract_version), v.digest);
  }
  for (const entry of baseline.tools) assert.equal(await contractDigest(entry.definition), entry.digest);
  assert.equal(canonicalValue(0), canonicalValue(-0));
});

test("unknown fields retained, arrays ordered, and unsafe values rejected", async () => {
  const tool = { name: "test", inputSchema: { b: 1, a: { type: "string" } } };
  assert.equal(await contractDigest(tool), await contractDigest({ inputSchema: { a: { type: "string" }, b: 1 }, name: "test" }));
  assert.notEqual(await contractDigest(tool), await contractDigest({ ...tool, inputSchema: { ...tool.inputSchema, "x-vendor": [1, 2] } }));
  assert.notEqual(canonicalValue([1, 2]), canonicalValue([2, 1]));
  for (const value of [NaN, Infinity, 2 ** 53, "\ud800", undefined]) assert.throws(() => canonicalValue(value));
});

test("flag is default off and malformed warnings contain no values", () => {
  const warnings = [];
  for (const value of [undefined, "", false, "false", "0"]) assert.equal(digestsEnabled(value, m => warnings.push(m)), false);
  assert.equal(warnings.length, 0);
  assert.equal(digestsEnabled("bad", m => warnings.push(m)), false);
  assert.equal(digestsEnabled("bad", m => warnings.push(m)), false);
  assert.equal(warnings.length, 1);
  assert.ok(!warnings[0].includes("bad"));
  for (const value of [true, "true", "1", " TRUE "]) assert.equal(digestsEnabled(value), true);
});

test("discovery digests describe only authorized tools and preserve off output", async () => {
  const result = await discoveryContract(catalogue.tools, ["knowledge:read"], { toolsets: ["core"], enabled: true });
  assert.deepEqual(result.tools.map(t => t.name), ["knowledge_context", "knowledge_search", "knowledge_artifact"]);
  assert.equal(result._meta.contract_digest, await catalogueDigest(result.tools));
  assert.ok(result.tools.every(t => t._meta.contract_digest));
  const plain = await discoveryContract(catalogue.tools, ["knowledge:read"], { toolsets: ["core"] });
  assert.deepEqual(plain, { tools: catalogue.tools.filter(e => e.toolset === "core").map(e => e.definition) });
  assert.notEqual(result._meta.contract_digest, (await discoveryContract(catalogue.tools, ["knowledge:manage"], { enabled: true }))._meta.contract_digest);
  assert.deepEqual(catalogue.tools.map(e => e.definition), baseline.tools.map(e => e.definition));
});

test("native pin mismatch denies before storage, billing or fetch; disabled ignores header", async () => {
  let calls = 0;
  const authority = { call: async () => { calls++; throw new Error("dispatch reached"); } };
  await assert.rejects(dispatchNative({ MCP_CONTRACT_DIGESTS_ENABLED: "true" }, authority, principal, "native.exa_search", { query: "x" }, { contractPin: "0".repeat(64) }), { code: "mcp_contract_mismatch", status: 409 });
  assert.equal(calls, 0);
  await assert.rejects(dispatchNative({}, authority, principal, "native.exa_search", { query: "x" }, { contractPin: "bad" }), /dispatch reached/);
  assert.equal(calls, 1);
  const f = await fixture();
  let fetched = 0;
  const fetchImpl = async () => { fetched++; return Response.json({ results: [] }); };
  const definition = catalogue.tools.find(e => e.definition.name === "knowledge_exa_search").definition;
  const pin = await contractDigest(definition);
  const plain = await dispatchNative(f.env, f.authority, principal, "native.exa_search", { query: "x" }, { fetchImpl, contractPin: "bad" });
  f.env.MCP_CONTRACT_DIGESTS_ENABLED = "true";
  const matched = await dispatchNative(f.env, f.authority, principal, "native.exa_search", { query: "x" }, { fetchImpl, contractPin: pin });
  const unpinned = await dispatchNative(f.env, f.authority, principal, "native.exa_search", { query: "x" }, { fetchImpl });
  assert.deepEqual(plain, matched);
  assert.deepEqual(plain, unpinned);
  assert.equal(fetched, 3);
});

test("pin helper bypasses disabled and unpinned calls without hashing", async () => {
  await checkContractPin(null, "bad", { enabled: false });
  await checkContractPin(null, undefined, { enabled: true });
  await assert.rejects(checkContractPin(baseline.vectors[0].definition, "bad", { enabled: true }), { code: "mcp_contract_mismatch", status: 409 });
});


test("canonical operational bounds reject oversized and deep schemas", () => {
  let deep = null;
  for (let i = 0; i < 66; i++) deep = [deep];
  for (const value of [deep, Array(65537).fill(null), "x".repeat(256 * 1024)]) assert.throws(() => canonicalValue(value));
});


const edgeWorker = (await loadWorkerModule()).default;
const edgeReader = await generateIntegrationCredential();
function edgeEnvironment(flag) {
  const dispatched = [];
  const env = {
    ADMIN_API_KEY: "synthetic-contract-admin", AUTH_STORAGE_BACKEND: "d1",
    INTELLIGENCE_DB: { prepare() { return { bind() { return { async first() {
      return { id: "integration:contract", scopes: JSON.stringify(["knowledge:read"]), version: 1,
        created_at: "2026-10-09T00:00:00Z", revoked_at: null, key_prefix: edgeReader.keyPrefix, key_hash: edgeReader.keyHash };
    } }; } }; } },
    KNOWLEDGE_SERVICE: { async fetch(_url, init) {
      dispatched.push(JSON.parse(init.body));
      return Response.json({ version: 1, result: { status: "ok" } });
    } },
    MULTILLM_PROXY_CONTAINER: { getByName() { throw new Error("unexpected Container dispatch"); } },
  };
  if (flag !== undefined) env.MCP_CONTRACT_DIGESTS_ENABLED = flag;
  return { env, dispatched };
}
function edgeRequest(method, params = {}, pin, { key = "synthetic-contract-admin", toolsets } = {}) {
  return new Request(`https://gateway.example/mcp${toolsets ? `?toolsets=${toolsets}` : ""}`, {
    method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json",
      ...(pin === undefined ? {} : { "X-MultiLLM-MCP-Contract": pin }) },
    body: JSON.stringify({ jsonrpc: "2.0", id: 7, method, params }),
  });
}
const responseBytes = async response => ({ status: response.status, headers: [...response.headers], body: await response.text() });

test("registered edge MCP disabled flags preserve response bytes, headers and dispatch payloads", async () => {
  const requests = [["tools/list", {}], ["tools/call", { name: "knowledge_context", arguments: { query: "limits" } }]];
  for (const flag of [undefined, "", "false", "0", "malformed"]) {
    const { env, dispatched } = edgeEnvironment();
    const expected = [];
    for (const [method, params] of requests) expected.push(await responseBytes(await edgeWorker.fetch(edgeRequest(method, params), env)));
    assert.deepEqual(JSON.parse(expected[0].body), { jsonrpc: "2.0", id: 7, result: { tools: catalogue.tools.map(e => e.definition) } });
    if (flag !== undefined) env.MCP_CONTRACT_DIGESTS_ENABLED = flag;
    for (const [index, [method, params]] of requests.entries()) {
      for (const pin of [undefined, "", "bad", "0".repeat(64)]) {
        assert.deepEqual(await responseBytes(await edgeWorker.fetch(edgeRequest(method, params, pin), env)), expected[index]);
      }
    }
    assert.equal(dispatched.length, 5);
    for (const payload of dispatched) assert.deepEqual(payload, dispatched[0]);
  }
});

test("registered edge enabled discovery hashes only authorized contracts and selected toolsets", async () => {
  const { env, dispatched } = edgeEnvironment("true");
  for (const options of [{}, { key: edgeReader.key }, { key: edgeReader.key, toolsets: "core" }]) {
    const response = await edgeWorker.fetch(edgeRequest("tools/list", {}, undefined, options), env);
    assert.equal(response.status, 200);
    const result = (await response.json()).result;
    const scopes = options.key ? ["knowledge:read"] : ["knowledge:read", "knowledge:manage"];
    assert.deepEqual(result, await discoveryContract(catalogue.tools, scopes,
      { enabled: true, toolsets: options.toolsets ? [options.toolsets] : null }));
    assert.equal(result._meta.contract_digest, await catalogueDigest(result.tools));
  }
  assert.equal(dispatched.length, 0);
});

test("registered edge mismatches return real HTTP 409 before dispatch for every tool kind", async () => {
  const { env, dispatched } = edgeEnvironment("true");
  for (const name of ["knowledge_context", "knowledge_exa_search", "knowledge_alexandria_inspect",
    "knowledge_policy_update", "knowledge_skills_sync", "knowledge_handoff_get"]) {
    for (const pin of ["", "bad", "0".repeat(64)]) {
      const response = await edgeWorker.fetch(edgeRequest("tools/call", { name, arguments: {} }, pin), env);
      assert.equal(response.status, 409);
      assert.deepEqual(await response.json(), { jsonrpc: "2.0", id: 7, error: {
        code: "mcp_contract_mismatch", message: "The pinned MCP tool contract has changed. Refresh discovery." } });
      assert.equal(response.headers.get("cache-control"), "no-store");
    }
  }
  assert.equal(dispatched.length, 0);
});

test("registered edge matching and unpinned calls preserve results; authorization precedes pins", async () => {
  const { env, dispatched } = edgeEnvironment();
  const params = { name: "knowledge_context", arguments: { query: "limits" } };
  const expected = await responseBytes(await edgeWorker.fetch(edgeRequest("tools/call", params), env));
  env.MCP_CONTRACT_DIGESTS_ENABLED = "true";
  const result = (await (await edgeWorker.fetch(edgeRequest("tools/list"), env)).json()).result;
  const tool = result.tools.find(t => t.name === params.name);
  for (const pin of [undefined, tool._meta.contract_digest]) {
    assert.deepEqual(await responseBytes(await edgeWorker.fetch(edgeRequest("tools/call", params, pin), env)), expected);
  }
  const stale = await contractDigest({ ...tool, inputSchema: { ...tool.inputSchema, "x-revision": "older" } });
  assert.equal((await edgeWorker.fetch(edgeRequest("tools/call", params, stale), env)).status, 409);
  assert.deepEqual(await responseBytes(await edgeWorker.fetch(edgeRequest("tools/call", params), env)), expected);
  const denied = await edgeWorker.fetch(edgeRequest("tools/call", { name: "knowledge_policy_update" }, "bad", { key: edgeReader.key }), env);
  assert.equal(denied.status, 200);
  assert.match((await denied.json()).result.content[0].text, /insufficient_scope/);
  assert.equal(dispatched.length, 4);
});
