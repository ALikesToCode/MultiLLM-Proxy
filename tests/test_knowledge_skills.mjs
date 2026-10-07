import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { SkillsStore } from "../worker/knowledge/skills-store.mjs";
import { SkillsIndex } from "../worker/knowledge/skills-index.mjs";
import { parseFind, parseGet, parseSync, validateSkill, SKILLS_LIMIT } from "../worker/knowledge/skills-validation.mjs";
import { quantizeEmbedding } from "../worker/knowledge/memo-store.mjs";
import { digest } from "../worker/knowledge/evidence.mjs";
import { dispatchKnowledge } from "../worker/knowledge/service.mjs";
import { handleKnowledgeEdgeRequest } from "../worker/knowledge-edge.mjs";

async function skill(name = "testing", description = "Test regression behavior", root = "agents", extra = []) {
  const content = `---\nname: ${name}\ndescription: ${description}\n---\n# ${name}\nTest guide`;
  return { skill_id: name, name, description, root, files: [{ path: "SKILL.md", content, sha256: await digest(content) }, ...extra] };
}
function fixture(t, options = {}) {
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  const storage = { sql: { exec: (query, ...args) => db.prepare(query).all(...args) }, transactionSync(callback) {
    db.exec("BEGIN");
    try { const result = callback(); db.exec("COMMIT"); return result; }
    catch (error) { db.exec("ROLLBACK"); throw error; }
  } };
  const files = new Map();
  const env = { KNOWLEDGE_SNAPSHOTS: { put: async (key, bytes) => files.set(key, bytes), delete: async keys => { for (const key of keys) files.delete(key); }, get: async key => {
    const bytes = files.get(key); return bytes && { arrayBuffer: async () => bytes.buffer };
  } } };
  const store = new SkillsStore(storage, env, options);
  const submit = (operation, payload, scopes = ["knowledge:read", "knowledge:manage"], id = "synthetic-principal") =>
    dispatchKnowledge(env, { version: 1, operation: `skills.${operation}`, principal: { id, scopes }, payload }, { skills: store });
  return { store, env, files, submit };
}

test("create, unchanged, update, root conflicts, dry run and delete preserve counters and files", async t => {
  const f = fixture(t);
  const first = await skill();
  const sync = payload => f.submit("sync", payload);
  assert.deepEqual(await sync({ skills: [first], dry_run: true }), { results: [{ skill_id: "testing", status: "created" }] });
  assert.equal(f.files.size, 0);
  assert.equal((await sync({ skills: [first] })).results[0].status, "created");
  assert.equal((await sync({ skills: [first] })).results[0].status, "unchanged");
  assert.equal(f.files.size, 1);
  const conflict = await skill("testing", "Other root", "codex");
  assert.equal((await sync({ skills: [conflict] })).results[0].reason, "root_conflict");
  const revised = await skill("testing", "Updated test guide");
  assert.equal((await sync({ skills: [revised] })).results[0].status, "updated");
  assert.equal((await sync({ skills: [], delete: ["testing"], dry_run: true })).results[0].status, "deleted");
  assert.ok(f.store.read("testing"));
  assert.equal((await sync({ skills: [], delete: ["testing"] })).results[0].status, "deleted");
  await assert.rejects(f.submit("get", { skill_id: "testing" }), { code: "skill_missing" });
});

test("sync rejects only secret-bearing skills, including base64, and never sends their metadata to embeddings", async t => {
  const inputs = [], f = fixture(t, { embed: async text => { inputs.push(text); return [1, 0]; } });
  const content = "gh" + "p_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5";
  const secret = await skill("unsafe", "Unsafe guide", "agents", [{ path: "scripts/run.py", content_base64: btoa(content), sha256: await digest(content) }]);
  const result = await f.submit("sync", { skills: [secret, await skill("safe")] });
  assert.deepEqual(result.results[0], { skill_id: "unsafe", status: "rejected", reason: "secret_detected", file: "scripts/run.py", types: ["github_token"] });
  assert.equal(result.results[1].status, "created");
  assert.deepEqual(inputs, ["safe: Test regression behavior"]);
  assert.equal(f.store.read("unsafe"), null);
  assert.ok(!JSON.stringify(result).includes(content));
  await assert.rejects(f.submit("find", { query: content }), { code: "secret_detected" });
});

test("weighted BM25, deterministic hybrid, root filters and silent embedding failure", async t => {
  let failed = false;
  const f = fixture(t, { embed: async text => {
    if (failed) throw new Error("synthetic failure");
    return text.startsWith("network:") || text === "database" ? [0, 1] : [1, 0];
  } });
  await f.submit("sync", { skills: [await skill("database", "Query tuning", "agents"), await skill("network", "Database networking", "codex")] });
  assert.equal((await f.submit("find", { query: "database", mode: "fast" }))[0].skill_id, "database");
  assert.equal((await f.submit("find", { query: "database" }))[0].skill_id, "network");
  assert.equal((await f.submit("find", { query: "database", roots: ["agents"] }))[0].skill_id, "database");
  failed = true;
  assert.equal((await f.submit("find", { query: "database" }))[0].skill_id, "database");
  assert.deepEqual(await f.submit("find", { query: "absentword", mode: "fast" }), []);
  const opposing = new SkillsIndex([{ skill_id: "database", name: "database", description: "Guide", index_text: "",
    files: [{ path: "SKILL.md" }], helpful: 0, embedding: quantizeEmbedding([-1, 0]) }]);
  assert.equal(opposing.find({ query: "database", limit: 3 }, quantizeEmbedding([1, 0]))[0].score, 0);
});

test("get text, binary file and principal-scoped helpful once per suggestion within 30 minutes", async t => {
  let now = 1000000;
  const f = fixture(t, { clock: () => now });
  const content = "Referenced file";
  const binary = Uint8Array.from([255, 0, 42]);
  await f.submit("sync", { skills: [await skill("testing", "Test guide", "agents", [
    { path: "references/test.md", content, sha256: await digest(content) },
    { path: "asset.bin", content_base64: btoa(String.fromCharCode(...binary)), sha256: await digest(binary) }])] });
  const get = (id = "synthetic-principal", path) => f.submit("get", { skill_id: "testing", ...(path ? { path } : {}) }, ["knowledge:read"], id);
  assert.equal((await get()).trust, "operator");
  assert.equal(f.store.read("testing").helpful, 0);
  await f.submit("find", { query: "test", mode: "fast" });
  await get("another-principal");
  assert.equal(f.store.read("testing").helpful, 0);
  assert.equal((await get("synthetic-principal", "references/test.md")).text, content);
  await get();
  assert.equal(f.store.read("testing").helpful, 1);
  assert.equal((await f.submit("find", { query: "test", mode: "fast" }))[0].score, 1 + Math.round(0.03 * Math.log(2) * 1000000) / 1000000);
  now += 30 * 60000 + 1;
  assert.equal((await get("synthetic-principal", "asset.bin")).content_base64, btoa(String.fromCharCode(...binary)));
  assert.equal(f.store.read("testing").helpful, 1);
  for (const path of ["../SKILL.md", "/SKILL.md", "a/../../x", "a\\x", "%2e%2e/x"]) await assert.rejects(get("synthetic-principal", path), { code: "invalid_path" });
});

test("contracts, file/hash limits and scope checks fail closed", async t => {
  const f = fixture(t);
  for (const payload of [{ query: "" }, { query: "x".repeat(2001) }, { query: "test", limit: 6 }, { query: "test", roots: ["unknown"] }, { query: "test", mode: "deep" }]) assert.throws(() => parseFind(payload));
  assert.throws(() => parseGet({ skill_id: "../test" }));
  assert.throws(() => parseSync({ skills: [], dry_run: "true" }));
  assert.throws(() => parseSync({ skills: [], delete: ["test", "test"] }));
  const first = await skill();
  for (const changes of [{ files: [] }, { files: Array(41).fill(first.files[0]) }, { files: [{ ...first.files[0], content: "x".repeat(65537) }] },
    { files: [{ ...first.files[0], sha256: "0".repeat(64) }] }, { name: "Different name" }]) {
    assert.equal((await f.submit("sync", { skills: [{ ...first, ...changes }] })).results[0].status, "rejected");
  }
  for (const op of ["find", "get"]) await assert.rejects(f.submit(op, {}, ["knowledge:manage"]), { code: "insufficient_scope" });
  await assert.rejects(f.submit("sync", { skills: [first] }, ["knowledge:read"]), { code: "insufficient_scope" });
  assert.equal(f.files.size, 0);
  const large = "x".repeat(256 * 1024 + 1);
  await assert.rejects(validateSkill(await skill("testing", "test", "agents", [{ path: "large.txt", content: large, sha256: await digest(large) }])), { code: "skill_limits" });
  const chunk = "x".repeat(256 * 1024), chunkHash = await digest(chunk);
  await assert.rejects(validateSkill(await skill("testing", "test", "agents", Array.from({ length: 21 }, (_, i) => ({ path: `${i}.txt`, content: chunk, sha256: chunkHash })))), { code: "skill_limits" });
});

test("2,000 skill lexical lookup includes JSON overhead well within hook budget", () => {
  const records = Array.from({ length: SKILLS_LIMIT }, (_, i) => ({ skill_id: `skill-${i}`, name: `skill ${i}`, description: `Testing database networking guide ${i}`,
    index_text: "# Example\n" + "Reference guide ".repeat(140), files: [{ path: "SKILL.md" }], helpful: 0 }));
  const index = new SkillsIndex(records);
  const start = performance.now();
  for (let i = 0; i < 20; i++) JSON.stringify(index.find({ query: "testing database", mode: "fast", limit: 3 }));
  const milliseconds = (performance.now() - start) / 20;
  console.log(`skills lexical 2000 + JSON: ${milliseconds.toFixed(2)} ms`);
  assert.ok(milliseconds < 100, `${milliseconds}ms must leave time for network and process startup`);
});

test("real Skills Durable Object survives restart with R2 files and helpful counters", async t => {
  const bundled = await build({ stdin: { resolveDir: process.cwd(), contents: `
    export { KnowledgeSkills } from './worker/knowledge/index.mjs';
    export default { fetch(request, env) { return env.KNOWLEDGE_SKILLS.get(env.KNOWLEDGE_SKILLS.idFromName('personal')).fetch(request); } };
  ` }, bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], write: false });
  const directory = await mkdtemp(join(tmpdir(), "knowledge-skills-"));
  const create = () => new Miniflare(convertV4MiniflareOptions({ cf: false, modules: true, compatibilityDate: "2026-07-28", script: bundled.outputFiles[0].text,
    resourcePersistencePath: directory, durableObjects: { KNOWLEDGE_SKILLS: { className: "KnowledgeSkills", useSQLite: true } }, r2Buckets: ["KNOWLEDGE_SNAPSHOTS"] }));
  let mf = create();
  t.after(async () => { await mf.dispose(); await rm(directory, { recursive: true, force: true }); });
  const call = async (operation, payload) => {
    const response = await mf.dispatchFetch("http://skills.internal/dispatch", { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ operation, payload, principal: "synthetic-principal" }) });
    assert.equal(response.status, 200);
    return (await response.json()).result;
  };
  await call("sync", { skills: [await skill()] });
  assert.equal((await call("find", { query: "testing", mode: "fast" }))[0].skill_id, "testing");
  assert.ok((await call("get", { skill_id: "testing" })).text.includes("Test guide"));
  await mf.dispose();
  mf = create();
  assert.ok((await call("get", { skill_id: "testing" })).text.includes("Test guide"));
  assert.equal((await call("find", { query: "testing", mode: "fast" }))[0].score, 1.020794);
});

test("edge REST/MCP parity, skills toolset and per-file firewall delegation", async t => {
  const f = fixture(t);
  const env = { ADMIN_API_KEY: "synthetic-skills-admin", ADMIN_USERNAME: "operator", KNOWLEDGE_SERVICE: { fetch: async (_url, init) => {
    const result = await dispatchKnowledge(f.env, JSON.parse(init.body), { skills: f.store });
    return Response.json({ version: 1, result });
  } } };
  const request = (path, method = "GET", body) => handleKnowledgeEdgeRequest(new Request(`https://gateway.example${path}`, {
    method, headers: { authorization: "Bearer synthetic-skills-admin", "content-type": "application/json" }, ...(body ? { body: JSON.stringify(body) } : {}) }), env);
  const rpc = (method, params, path = "/mcp") => request(path, "POST", { jsonrpc: "2.0", id: 1, method, params });
  const long = await skill("testing", "Test guide", "agents", [{ path: "reference.md", content: "x".repeat(100000), sha256: await digest("x".repeat(100000)) }]);
  assert.equal((await request("/v1/knowledge/skills", "POST", { skills: [long] })).status, 200);
  const listed = (await (await rpc("tools/list", {}, "/mcp?toolsets=skills")).json()).result.tools;
  assert.deepEqual(listed.map(tool => tool.name), ["knowledge_skills_find", "knowledge_skills_get", "knowledge_skills_sync"]);
  const rest = await (await request("/v1/knowledge/skills?query=test&mode=fast&limit=3&roots=agents")).json();
  const mcp = (await (await rpc("tools/call", { name: "knowledge_skills_find", arguments: { query: "test", mode: "fast", limit: 3, roots: ["agents"] } })).json()).result;
  assert.deepEqual(JSON.parse(mcp.content[0].text), rest);
  assert.equal(mcp.structuredContent, undefined);
  assert.equal((await (await request("/v1/knowledge/skills/testing?path=reference.md")).json()).text.length, 100000);
  assert.equal((await rpc("tools/call", { name: "knowledge_skills_sync", arguments: { skills: [long] } })).status, 200);
  const token = "gh" + "p_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5";
  const unsafe = await skill("unsafe", "Unsafe guide", "agents", [{ path: "reference.txt", content_base64: btoa(token), sha256: await digest(token) }]);
  const partial = { skills: [unsafe, long] };
  const synced = await (await request("/v1/knowledge/skills", "POST", partial)).json();
  assert.deepEqual(synced.results.map(item => [item.status, item.reason]), [["rejected", "secret_detected"], ["unchanged", undefined]]);
  const mcpSync = (await (await rpc("tools/call", { name: "knowledge_skills_sync", arguments: partial })).json()).result;
  assert.deepEqual(JSON.parse(mcpSync.content[0].text), synced);
  assert.equal((await request(`/v1/knowledge/skills?query=${token}&mode=fast`)).status, 422);
  assert.equal((await request("/v1/knowledge/skills?query=test&limit=bad")).status, 400);
});


test("obsolete and interrupted R2 uploads have bounded cleanup with retry backpressure", async t => {
  let now = 0;
  const f = fixture(t, { clock: () => now });
  const first = await skill(), revised = await skill("testing", "Revised description");
  await f.submit("sync", { skills: [first] });
  await f.submit("sync", { skills: [revised] });
  assert.equal(f.files.size, 2);
  const put = f.env.KNOWLEDGE_SNAPSHOTS.put;
  f.env.KNOWLEDGE_SNAPSHOTS.put = async (key, bytes) => { await put(key, bytes); throw new Error("synthetic upload failure"); };
  assert.equal((await f.submit("sync", { skills: [await skill("testing", "Interrupted revision")] })).results[0].status, "rejected");
  assert.equal((await f.submit("get", { skill_id: "testing" })).text, revised.files[0].content);
  assert.equal(f.files.size, 3);
  f.env.KNOWLEDGE_SNAPSHOTS.put = put;
  now = 60001;
  await f.submit("sync", { skills: [] });
  assert.equal(f.files.size, 1);
  for (let i = 0; i < 64; i++) f.store.enqueueCleanup({ skill_id: `obsolete-${i}`, content_hash: "0".repeat(64), files: [{ path: "SKILL.md" }] });
  assert.equal((await f.submit("sync", { skills: [await skill("new")] })).results[0].reason, "cleanup_backlog");
  assert.equal((await f.submit("sync", { skills: [], delete: ["testing"] })).results[0].reason, "cleanup_backlog");
  now += 60001;
  assert.equal((await f.submit("sync", { skills: [await skill("new")], delete: ["testing"] })).results[0].status, "created");
  now += 60001;
  await f.submit("sync", { skills: [] });
  assert.equal(f.files.size, 1);
});

test("2,000 skill full fast DO path, cold rebuild, JSON and capacity limit", async t => {
  const f = fixture(t);
  for (let i = 0; i < SKILLS_LIMIT; i++) {
    const record = { skill_id: `skill-${i}`, root: "agents", name: `skill ${i}`, description: `Testing database guide ${i}`,
      index_text: "Reference guide ".repeat(130), embedding: null, files: [{ path: "SKILL.md" }], content_hash: "0".repeat(64) };
    f.store.sql.exec("INSERT INTO skills VALUES (?, ?, ?, 0, 0, 0)", record.skill_id, record.root, JSON.stringify(record));
  }
  const coldStart = performance.now();
  JSON.stringify(await f.store.find({ query: "testing database", mode: "fast" }, "principal"));
  const cold = performance.now() - coldStart;
  const start = performance.now();
  for (let i = 0; i < 20; i++) JSON.stringify(await f.store.find({ query: "testing database", mode: "fast" }, "principal"));
  const warm = (performance.now() - start) / 20;
  console.log(`skills full DO fast 2000 + JSON: warm ${warm.toFixed(2)} ms; cold ${cold.toFixed(2)} ms`);
  assert.ok(warm < 10, `${warm} ms exceeds the fast work target`);
  assert.ok(cold < 600, `${cold} ms leaves insufficient hook budget`);
  assert.equal((await f.submit("sync", { skills: [await skill("overflow")] })).results[0].reason, "skills_limit");
  assert.equal((await f.submit("sync", { skills: [await skill("overflow")], dry_run: true })).results[0].reason, "skills_limit");
});

test("get fails integrity and concurrent-revision checks before feedback; concurrent sync serializes", { timeout: 4000 }, async t => {
  const f = fixture(t), first = await skill();
  await f.submit("sync", { skills: [first] });
  await f.submit("find", { query: "testing", mode: "fast" });
  const key = [...f.files.keys()][0], original = f.files.get(key);
  f.files.set(key, new TextEncoder().encode("corrupt"));
  await assert.rejects(f.submit("get", { skill_id: "testing" }), { code: "skill_corrupt" });
  assert.equal(f.store.read("testing").helpful, 0);
  f.files.set(key, original);
  const originalGet = f.env.KNOWLEDGE_SNAPSHOTS.get;
  let release, ready;
  const started = new Promise(resolve => { ready = resolve; });
  f.env.KNOWLEDGE_SNAPSHOTS.get = async target => { const object = await originalGet(target); await new Promise(resolve => { release = resolve; ready(); }); return object; };
  const reading = f.submit("get", { skill_id: "testing" });
  await started;
  await f.store.call("sync", { skills: [await skill("testing", "Updated")] });
  release();
  await assert.rejects(reading, { code: "skill_changed" });
  f.env.KNOWLEDGE_SNAPSHOTS.get = originalGet;
  await Promise.all([f.store.call("sync", { skills: [await skill("testing", "Second")] }), f.store.call("sync", { skills: [await skill("testing", "Third")] })]);
  assert.equal(f.store.read("testing").description, "Third");
});


test("publishing an update preserves feedback collected during its R2 upload", { timeout: 4000 }, async t => {
  const f = fixture(t);
  await f.store.call("sync", { skills: [await skill()] });
  const originalPut = f.env.KNOWLEDGE_SNAPSHOTS.put;
  let release, ready;
  const started = new Promise(resolve => { ready = resolve; });
  f.env.KNOWLEDGE_SNAPSHOTS.put = async (key, bytes) => {
    await new Promise(resolve => { release = resolve; ready(); });
    return originalPut(key, bytes);
  };
  const updating = f.store.call("sync", { skills: [await skill("testing", "Updated")] });
  await started;
  await f.store.find({ query: "testing", mode: "fast" }, "principal");
  await f.store.get({ skill_id: "testing" }, "principal");
  release();
  await updating;
  const record = f.store.read("testing");
  assert.equal(record.suggested, 1);
  assert.equal(record.fetched, 1);
  assert.equal(record.helpful, 1);
});


test("pending R2 operations prevent cleanup or reuse of their immutable revision", { timeout: 4000 }, async t => {
  let now = 0;
  const f = fixture(t, { clock: () => now }), first = await skill();
  await f.store.call("sync", { skills: [first] });
  const revision = f.store.read("testing");
  await f.store.call("sync", { skills: [await skill("testing", "Revised")] });
  let finish, ready;
  const started = new Promise(resolve => { ready = resolve; });
  const pending = f.store.r2(revision, () => new Promise(resolve => { finish = resolve; ready(); }));
  await started;
  now += 60001;
  assert.equal((await f.store.call("sync", { skills: [first] })).results[0].reason, "cleanup_backlog");
  assert.equal(f.files.size, 2);
  assert.equal(f.store.pendingR2.size, 1);
  finish();
  await pending;
  assert.equal((await f.store.call("sync", { skills: [first] })).results[0].status, "updated");
  assert.equal((await f.store.get({ skill_id: "testing" }, "principal")).text, first.files[0].content);
  assert.equal(f.store.pendingR2.size, 0);
});
