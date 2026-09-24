import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { defaultPolicy, validatePolicy } from "../worker/knowledge/policy.mjs";
import { createArtifact, normalizeSourceText, packEvidence, validateChunk, versionEvidence } from "../worker/knowledge/evidence.mjs";
import { parseQuery, publicUrl } from "../worker/knowledge/contracts.mjs";

const bundled = await build({ stdin: { resolveDir: process.cwd(), sourcefile: "knowledge-fixture.mjs", contents: `
  import { DurableObject } from 'cloudflare:workers';
  import { KnowledgeAuthority } from './worker/knowledge/authority.mjs';
  import { errorReply, reply } from './worker/knowledge/contracts.mjs';
  export class Catalogue extends DurableObject {
    async fetch(request) {
      const input = await request.json();
      try { return reply(await new KnowledgeAuthority(this.ctx.storage, () => input.now || Date.now()).call(input.operation, input.payload)); }
      catch (error) { return errorReply(error); }
    }
  }
  export default { fetch(request, env) { return env.CATALOGUE.get(env.CATALOGUE.idFromName('personal')).fetch(request); } };
` }, bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], write: false });

function enabledPolicy(limit = 10) {
  const { revision, ...policy } = defaultPolicy();
  policy.enabled = true;
  Object.assign(policy.providers.firecrawl, { enabled: true, limit, background_limit: limit,
    hard_limit_confirmed: true, retention_allowed: true });
  return { ...policy, expected_revision: revision };
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "knowledge-authority-"));
  const create = () => new Miniflare(convertV4MiniflareOptions({ cf: false, modules: true, compatibilityDate: "2026-07-28",
    script: bundled.outputFiles[0].text, resourcePersistencePath: directory,
    durableObjects: { CATALOGUE: { className: "Catalogue", useSQLite: true } } }));
  let mf = create();
  let now = Date.parse("2026-09-23T00:00:00Z");
  t.after(async () => { await mf.dispose(); await rm(directory, { recursive: true, force: true }); });
  return {
    async call(operation, payload = {}) {
      const response = await mf.dispatchFetch("http://catalogue.test/", { method: "POST", body: JSON.stringify({ operation, payload, now }) });
      return { status: response.status, ...await response.json() };
    },
    advance(ms) { now += ms; },
    async reopen() { await mf.dispose(); mf = create(); },
  };
}

test("Knowledge admission is disabled by default and validates every allocation", async t => {
  const f = await fixture(t);
  assert.equal((await f.call("snapshot")).result.policy.enabled, false);
  assert.equal((await f.call("reserve", { operation_id: "first", provider: "firecrawl", background: false })).status, 503);
  for (const change of [{ limit: Infinity }, { limit: true }, { units_per_call: 0 }, { hard_limit_confirmed: false }, { retention_allowed: false }]) {
    const policy = enabledPolicy();
    Object.assign(policy.providers.firecrawl, change);
    assert.throws(() => validatePolicy(policy));
  }
  assert.equal((await f.call("policy.update", enabledPolicy())).status, 200);
  assert.equal((await f.call("policy.update", enabledPolicy())).status, 409);
});

test("SQLite Durable Object serializes concurrent reservations and survives reopen", async t => {
  const f = await fixture(t);
  await f.call("policy.update", enabledPolicy(5));
  const attempts = await Promise.all(Array.from({ length: 25 }, (_, i) => f.call("reserve", {
    operation_id: `query-${i}`, provider: "firecrawl", background: false,
  })));
  assert.equal(attempts.filter(item => item.status === 200).length, 5);
  assert.equal(attempts.filter(item => item.status === 429).length, 20);
  await f.reopen();
  const usage = (await f.call("snapshot")).result.usage.find(item => item.provider === "firecrawl");
  assert.equal(usage.total, 5);
  assert.equal(usage.pending, 5);
  assert.equal((await f.call("reserve", { operation_id: "query-0", provider: "firecrawl", background: false })).result.replay, true);
  assert.equal((await f.call("reserve", { operation_id: "query-0", provider: "exa", background: false })).status, 409);
});

test("credential failover persists across SQLite restarts and concurrent selection", async t => {
  const f = await fixture(t);
  const fingerprints = ["a".repeat(64), "b".repeat(64), "c".repeat(64)];
  const selection = { provider: "context7", fingerprints, excluded: [] };
  const select = () => f.call("credentials.select", selection);
  const reject = fingerprint => f.call("credentials.reject", {
    provider: "context7", fingerprint, reason: "quota", cooldown_seconds: 120,
  });
  assert.equal((await select()).result.fingerprint, fingerprints[0]);
  await reject(fingerprints[0]);
  const concurrent = await Promise.all(Array.from({ length: 10 }, select));
  assert.ok(concurrent.every(item => item.result.fingerprint === fingerprints[1]));
  await f.reopen();
  assert.equal((await select()).result.fingerprint, fingerprints[1]);
  // A request from another deployment with a different list cannot clear a cooldown.
  await f.call("credentials.select", { ...selection, fingerprints: [fingerprints[1]] });
  await reject(fingerprints[1]);
  assert.equal((await select()).result.fingerprint, fingerprints[2]);
  await reject(fingerprints[2]);
  assert.equal((await select()).result.fingerprint, null);
  await f.reopen();
  assert.equal((await select()).result.fingerprint, null);
  f.advance(121000);
  assert.equal((await select()).result.fingerprint, fingerprints[0]);
  assert.equal((await f.call("credentials.select", { ...selection, key: "not-accepted" })).status, 400);
  assert.equal((await f.call("credentials.select", { ...selection, fingerprints: ["raw-secret"] })).status, 400);
  assert.equal((await f.call("credentials.select", { ...selection, provider: "alexandria" })).status, 400);
});

test("background work preserves interactive reserve and uncertain work outlives the daily window", async t => {
  const f = await fixture(t);
  const policy = enabledPolicy(4);
  policy.providers.firecrawl.interactive_reserve = 2;
  await f.call("policy.update", policy);
  for (let i = 0; i < 2; i++) assert.equal((await f.call("reserve", { operation_id: `bg-${i}`, provider: "firecrawl", background: true })).status, 200);
  assert.equal((await f.call("reserve", { operation_id: "bg-2", provider: "firecrawl", background: true })).status, 429);
  await f.call("settle", { id: "bg-0", outcome: "unknown" });
  await f.call("settle", { id: "bg-1", outcome: "confirmed" });
  f.advance(2 * 86400000);
  await f.reopen();
  const usage = (await f.call("snapshot")).result.usage.find(item => item.provider === "firecrawl");
  assert.equal(usage.unknown, 1);
  assert.equal(usage.confirmed, 0);
  assert.equal((await f.call("settle", { id: "bg-0", outcome: "confirmed" })).result.state, "unknown");
});

test("source disabling cancels jobs and fences stale publication", async t => {
  const f = await fixture(t);
  const source = (await f.call("source.create", { url: "https://flask.palletsprojects.com/en/3.1.3/api/", product: "flask", version: "3.1.3" })).result;
  const job = (await f.call("job.enqueue", { source_id: source.id })).result;
  assert.equal((await f.call("job.enqueue", { source_id: source.id })).result.id, job.id);
  const artifact = await createArtifact(source, "A real source passage.", "firecrawl");
  await f.call("artifact.save", { artifact });
  await f.call("source.update", { id: source.id, expected_revision: 1, enabled: false });
  assert.equal((await f.call("job.get", { id: job.id })).result.job.status, "cancelled");
  assert.equal((await f.call("job.publish", { id: job.id, artifact_id: artifact.id, item_id: "item", index_key: artifact.index_key })).status, 409);
  await f.call("source.update", { id: source.id, expected_revision: 2, enabled: true });
  const replacement = (await f.call("job.enqueue", { source_id: source.id })).result;
  assert.notEqual(replacement.id, job.id);
  assert.ok(replacement.fence > job.fence);
});

test("revision claims prevent cross-job replay and expiration fences concurrent refresh", async t => {
  const f = await fixture(t);
  const policy = enabledPolicy(20);
  policy.providers.ai_search = { ...policy.providers.firecrawl };
  await f.call("policy.update", policy);
  const source = (await f.call("source.create", { url: "https://react.dev/docs", product: "react" })).result;
  const artifact = await createArtifact({ ...source, origin_checked: true }, "Retained source.", "firecrawl", Date.parse("2026-09-23T00:00:00Z"));
  await f.call("artifact.save", { artifact });
  const job = (await f.call("job.enqueue", { source_id: source.id })).result;
  const operation = { operation_id: `${job.id}:upload`, provider: "ai_search", background: true, job_id: job.id, revision_id: artifact.id };
  assert.equal((await f.call("reserve", operation)).result.replay, false);
  await f.call("settle", { id: operation.operation_id, outcome: "confirmed" });
  await f.call("job.cancel", { id: job.id });
  const next = (await f.call("job.enqueue", { source_id: source.id })).result;
  assert.equal((await f.call("reserve", { ...operation, operation_id: `${next.id}:upload`, job_id: next.id })).result.replay, true);
  const cached = (await f.call("artifact.save", { artifact: { ...artifact, checked_at: null } })).result;
  assert.equal(cached.checked_at, artifact.checked_at);
  f.advance(31 * 86400000);
  await f.call("maintenance");
  await f.reopen();
  assert.equal((await f.call("reserve", { ...operation, operation_id: `${next.id}:upload`, job_id: next.id })).result.replay, true);
  assert.equal((await f.call("artifact.expiration_claim", { id: artifact.id, expires_at: "wrong" })).status, 409);
  assert.equal((await f.call("artifact.expiration_claim", artifact)).status, 200);
  assert.equal((await f.call("artifact.save", { artifact: { ...artifact, expires_at: "2026-12-01T00:00:00Z" } })).status, 409);
  assert.equal((await f.call("artifact.expire", artifact)).status, 200);
  assert.equal((await f.call("artifact.get", { id: artifact.id })).result, null);
});

test("source policy rejects credentials, private origins and significant invalid requests", () => {
  for (const url of ["http://react.dev", "https://127.0.0.1/", "https://foo.internal/", "https://u:p@react.dev/", "https://react.dev/?api_key=secret", "https://unapproved.example/"]) {
    assert.throws(() => publicUrl(url, ["react.dev"]));
  }
  assert.equal(publicUrl("https://react.dev/page?version=3#section", ["react.dev"]), "https://react.dev/page?version=3");
  for (const payload of [{ query: "test", version: "3" }, { query: "test", token_budget: true }, { query: "test", repository: "../private/repo" }, { query: "test", extra: "field" }]) {
    assert.throws(() => parseQuery(payload));
  }
});

test("Alexandria prices and replay fences survive SQLite restart and ledger maintenance", async t => {
  const f = await fixture(t);
  const policy = enabledPolicy(30);
  policy.providers.alexandria = { ...policy.providers.firecrawl };
  await f.call("policy.update", policy);
  const tool = { provider: "particle", capability: "podcasts/episodes/search", creditsCost: 15, perRecord: false, options: [] };
  const quotes = (await f.call("alexandria.quotes", { principal_id: "reader", tools: [tool] })).result;
  const input = { principal_id: "reader", receipt_id: "alexandria:test", request_id: "request-1", quote_id: quotes[0].quote_id,
    fingerprint: "same-request", reserve_credits: 20, options: {} };
  assert.equal((await f.call("alexandria.begin", input)).result.replay, false);
  await f.call("alexandria.finish", { ...input, status: "ok", credits: 15, scrape_id: "scrape-1" });
  await f.reopen();
  assert.equal((await f.call("alexandria.receipt", input)).result.cost.credits, 15);
  assert.equal((await f.call("snapshot")).result.usage.find(row => row.provider === "alexandria").confirmed, 15);
  f.advance(35 * 86400000);
  await f.call("maintenance");
  await f.reopen();
  assert.equal((await f.call("alexandria.begin", input)).result.replay, true);
  assert.equal((await f.call("alexandria.receipt", { ...input, principal_id: "other" })).status, 404);
});

test("source spans use exact UTF-8 bytes and version requests are never treated as proof", async () => {
  const text = normalizeSourceText("  Title\r\nCafé 東京 documentation.  ");
  const source = { id: "a".repeat(64), url: "https://flask.palletsprojects.com/en/stable/", product: "flask", version: "3.1.3" };
  const artifact = await createArtifact(source, text, "firecrawl");
  assert.deepEqual(artifact.version, { kind: "unknown" });
  const excerpt = validateChunk(artifact, text, "東京");
  assert.equal(excerpt.locator.start_byte, Buffer.byteLength("Title\nCafé "));
  assert.equal(excerpt.locator.end_byte - excerpt.locator.start_byte, 6);
  assert.equal(validateChunk(artifact, text, "invented text"), null);
  assert.equal(versionEvidence("https://example.com/v3.1.3/docs", "3.1.3").kind, "unknown");
  assert.equal(versionEvidence("https://github.com/unrelated/project/blob/main/examples/3.1.3/docs", "3.1.3", { product: "flask" }).kind, "unknown");
  assert.equal(versionEvidence("https://github.com/pallets/flask/blob/3.1.3/docs", "3.1.3", { product: "flask" }).kind, "exact");
  const packed = packEvidence([{ ...excerpt, target_match: "unverified" }], { token_budget: 500 });
  assert.equal(packed.excerpts.length, 0);
  assert.equal(packed.related_evidence.length, 1);
  const long = validateChunk(artifact, "東京 ".repeat(1000), "東京 ".repeat(1000));
  const clipped = packEvidence([{ ...long, target_match: "exact" }], { token_budget: 256 });
  assert.equal(clipped.excerpts.length, 1);
  assert.ok(clipped.token_count <= 256);
  assert.equal(clipped.excerpts[0].locator.end_byte, Buffer.byteLength(clipped.excerpts[0].text));
});
