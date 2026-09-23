import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { Miniflare } from "miniflare";
import { KnowledgeCorpus } from "../worker/knowledge/corpus.mjs";

const text = "# Flask 3.1\n\nRequest limits support café and 東京.\n";
const digest = value => createHash("sha256").update(value).digest("hex");
const artifact = (value = text) => ({
  id: "artifact-one", snapshot_key: `snapshots/${digest(value)}.txt`,
  index_key: `revisions/${digest(value)}.md`, content_hash: digest(value),
  byte_length: Buffer.byteLength(value), product: "flask", version: { kind: "unknown" },
});

function fixture() {
  const objects = new Map();
  const uploads = [];
  const searches = [];
  const lists = [];
  let currentItem = { id: "item-one", key: artifact().index_key, status: "completed" };
  let chunks = [{ text, start_byte: 0, end_byte: Buffer.byteLength(text) }];
  const bucket = {
    async put(key, bytes, options) {
      assert.equal(options.onlyIf.etagDoesNotMatch, "*");
      assert.equal(options.sha256, digest(bytes));
      if (objects.has(key)) return null;
      objects.set(key, new Uint8Array(bytes));
      return { key };
    },
    async get(key) {
      const bytes = objects.get(key);
      return bytes ? { size: bytes.byteLength, body: new Response(bytes).body } : null;
    },
  };
  const index = {
    async search(request) {
      searches.push(request);
      return { chunks: [{ text, score: 0.8, item: { key: artifact().index_key } }] };
    },
    items: {
      async upload(key, content, options) {
        uploads.push({ key, content, options });
        return currentItem;
      },
      async list(params) {
        assert.ok(params.per_page <= 50, "AI Search limits item pages to 50 records");
        lists.push(params);
        return { result: [currentItem] };
      },
      get(id) {
        assert.equal(id, "item-one");
        return {
          async info() { return currentItem; },
          async chunks({ offset, limit }) {
            return { result: chunks.slice(offset, offset + limit), result_info: { total: chunks.length, offset } };
          },
        };
      },
    },
  };
  return {
    corpus: new KnowledgeCorpus({ KNOWLEDGE_SNAPSHOTS: bucket, KNOWLEDGE_INDEX: index }),
    objects, uploads, searches, lists, bucket, index,
    set item(value) { currentItem = value; },
    get chunks() { return chunks; },
    set chunks(value) { chunks = value; },
  };
}

test("snapshots are immutable, hash checked and readable across corpus instances", async () => {
  const f = fixture();
  const revision = artifact();
  assert.equal(await f.corpus.getSnapshot(revision), null);
  await f.corpus.putSnapshot(revision, text);
  await f.corpus.putSnapshot(revision, text);
  assert.equal(f.objects.size, 1);
  const restarted = new KnowledgeCorpus({ KNOWLEDGE_SNAPSHOTS: f.bucket });
  assert.equal(await restarted.getSnapshot(revision), text);
  await assert.rejects(f.corpus.putSnapshot(revision, `${text}tampered`), { code: "invalid_snapshot" });
  f.objects.set(revision.snapshot_key, new TextEncoder().encode("corrupt"));
  await assert.rejects(f.corpus.getSnapshot(revision), { code: "invalid_snapshot" });
  await assert.rejects(f.corpus.putSnapshot(revision, text), { code: "invalid_snapshot" });
});

test("the real local R2 binding honors immutable snapshot preconditions", async t => {
  const runtime = new Miniflare({
    cf: false, modules: true, script: "export default { fetch() { return new Response('ok'); } };",
    r2Buckets: { KNOWLEDGE_SNAPSHOTS: "knowledge-snapshot-test" },
  });
  t.after(() => runtime.dispose());
  const bucket = await runtime.getR2Bucket("KNOWLEDGE_SNAPSHOTS");
  const corpus = new KnowledgeCorpus({ KNOWLEDGE_SNAPSHOTS: bucket });
  await corpus.putSnapshot(artifact(), text);
  const initial = await bucket.head(artifact().snapshot_key);
  await corpus.putSnapshot(artifact(), text);
  const repeated = await bucket.head(artifact().snapshot_key);
  assert.equal(repeated.version, initial.version);
  assert.equal(await corpus.getSnapshot(artifact()), text);
});

test("snapshot limits apply to UTF-8 bytes, object metadata and streamed content", async () => {
  const f = fixture();
  await assert.rejects(f.corpus.putSnapshot(artifact("é".repeat(140000)), "é".repeat(140000)), { code: "invalid_snapshot" });
  f.bucket.get = async () => ({ size: 256 * 1024 + 1, body: new Response("small").body });
  await assert.rejects(f.corpus.getSnapshot(artifact()), { code: "snapshot_too_large" });
  f.bucket.get = async () => ({ size: 1, body: new Response("x".repeat(256 * 1024 + 1)).body });
  await assert.rejects(f.corpus.getSnapshot(artifact()), { code: "snapshot_too_large" });
  f.bucket.get = async () => ({ size: 1, body: new Response(new Uint8Array([255])).body });
  await assert.rejects(f.corpus.getSnapshot(artifact()), { code: "invalid_snapshot" });
});

test("search disables generated stages and semantic caching and preserves failure", async () => {
  const f = fixture();
  assert.deepEqual(await f.corpus.search({ query: "request limits", product: "flask", version: "3.1.3" }),
    [{ text, index_key: artifact().index_key, score: 0.8 }]);
  const options = f.searches[0].ai_search_options;
  assert.equal(options.retrieval.return_on_failure, false);
  assert.equal(options.retrieval.retrieval_type, "hybrid");
  assert.deepEqual(options.retrieval.filters, { product: "flask" });
  for (const stage of ["query_rewrite", "reranking", "cache"]) assert.equal(options[stage].enabled, false);
  f.index.search = async () => { throw new Error("upstream outage"); };
  await assert.rejects(f.corpus.search({ query: "limits" }), /upstream outage/);
  f.index.search = async () => ({ chunks: [{ text, score: NaN, item: { key: "foo" } }] });
  await assert.rejects(f.corpus.search({ query: "limits" }), { code: "invalid_index_response" });
});

test("upload checks snapshot bytes and returns only matching item identity", async () => {
  const f = fixture();
  f.item = { id: "item-one", key: artifact().index_key };
  await f.corpus.uploadRevision(artifact(), text);
  assert.equal(f.uploads.length, 1);
  assert.equal(f.uploads[0].options.metadata.version, "unknown");
  f.item = { id: "different", key: "unrelated.md", status: "completed" };
  await assert.rejects(f.corpus.uploadRevision(artifact(), text), { code: "invalid_index_response" });
});

test("binding context failures retry metadata reads only and remain bounded", async () => {
  const f = fixture();
  let calls = 0;
  const contextError = () => new Error("Invalid ctx.props: missing accountId or accountTag");
  f.index.items.list = async () => {
    if (++calls < 3) throw contextError();
    return { result: [{ id: "item-one", key: artifact().index_key, status: "completed" }] };
  };
  assert.equal((await f.corpus.reconcileRevision(artifact())).id, "item-one");
  assert.equal(calls, 3);
  calls = 0;
  f.index.items.list = async () => { calls += 1; throw contextError(); };
  await assert.rejects(f.corpus.reconcileRevision(artifact()), /missing accountId/);
  assert.equal(calls, 3);
  calls = 0;
  f.index.items.list = async () => { calls += 1; throw new Error("other failure"); };
  await assert.rejects(f.corpus.reconcileRevision(artifact()), /other failure/);
  assert.equal(calls, 1);
  calls = 0;
  f.index.items.upload = async () => { calls += 1; throw contextError(); };
  await assert.rejects(f.corpus.uploadRevision(artifact(), text), /missing accountId/);
  assert.equal(calls, 1);
  calls = 0;
  f.index.search = async () => { calls += 1; throw contextError(); };
  await assert.rejects(f.corpus.search({ query: "limits" }), /missing accountId/);
  assert.equal(calls, 1);
});

test("reconciliation uses item info and exact built-in key matches without uploading", async () => {
  const f = fixture();
  assert.equal((await f.corpus.reconcileRevision(artifact(), "item-one")).id, "item-one");
  assert.equal((await f.corpus.reconcileRevision(artifact())).id, "item-one");
  assert.equal(f.lists[0].source, "builtin");
  f.index.items.list = async () => ({ result: [{ id: "similar", key: `${artifact().index_key}-other`, status: "completed" }] });
  assert.equal(await f.corpus.reconcileRevision(artifact()), null);
  assert.equal(f.uploads.length, 0);
  f.index.items.list = async () => ({ result: Array.from({ length: 50 }, (_, i) => ({ key: `other-${i}` })) });
  await assert.rejects(f.corpus.reconcileRevision(artifact()), { code: "index_reconciliation_incomplete" });
});

test("reconciliation follows full 50-item pages to find a later exact revision", async () => {
  const f = fixture();
  const pages = [];
  f.index.items.list = async ({ page, per_page }) => {
    assert.equal(per_page, 50);
    pages.push(page);
    return { result: page === 1 ? Array.from({ length: 50 }, (_, i) => ({ key: `other-${i}` }))
      : [{ id: "item-one", key: artifact().index_key, status: "completed" }], result_info: { total_count: 51 } };
  };
  assert.equal((await f.corpus.reconcileRevision(artifact())).id, "item-one");
  assert.deepEqual(pages, [1, 2]);
});

test("readiness requires completed status and exact indexed UTF-8 byte spans", async () => {
  const f = fixture();
  await f.corpus.putSnapshot(artifact(), text);
  const item = await f.corpus.reconcileRevision(artifact());
  assert.equal(await f.corpus.verifySearchable(artifact(), item), true);
  assert.equal(await f.corpus.verifySearchable(artifact(), { ...item, status: "running" }), false);
  assert.equal(await f.corpus.verifySearchable(artifact(), { ...item, next_action: "DELETE" }), false);
  assert.equal(await f.corpus.verifySearchable(artifact(), { ...item, next_action: "INDEX" }), false);
  f.chunks = [{ text: "東京", start_byte: Buffer.byteLength(text.slice(0, text.indexOf("東京"))),
    end_byte: Buffer.byteLength(text.slice(0, text.indexOf("東京") + 2)) }];
  assert.equal(await f.corpus.verifySearchable(artifact(), item), true);
  f.chunks[0].end_byte -= 1;
  assert.equal(await f.corpus.verifySearchable(artifact(), item), false);
  f.chunks = [{ text: "A generated answer", start_byte: 0, end_byte: 18 }];
  assert.equal(await f.corpus.verifySearchable(artifact(), item), false);
});

test("missing bindings and corrupt chunk pagination fail closed", async () => {
  const empty = new KnowledgeCorpus({});
  await assert.rejects(empty.search({ query: "limits" }), { code: "index_unavailable" });
  await assert.rejects(empty.getSnapshot(artifact()), { code: "snapshot_storage_unavailable" });
  const f = fixture();
  await f.corpus.putSnapshot(artifact(), text);
  f.index.items.get = () => ({ async chunks() { return { result: [], result_info: { total: 1, offset: 0 } }; } });
  assert.equal(await f.corpus.verifySearchable(artifact(), { id: "item-one", key: artifact().index_key, status: "completed" }), false);
});

test("expiry cleanup only removes the named immutable artifact and is repeatable", async () => {
  const f = fixture();
  const id = "a".repeat(64);
  const revision = { ...artifact(), id, snapshot_key: `snapshots/${id}.txt`,
    index_key: `revisions/${id}.txt`, item_id: "item-one" };
  const removed = [];
  f.item = { id: "item-one", key: revision.index_key, status: "completed" };
  f.index.items.delete = async itemId => {
    removed.push(itemId);
    f.index.items.list = async () => ({ result: [] });
  };
  f.bucket.delete = async key => { removed.push(key); f.objects.delete(key); };
  await f.corpus.putSnapshot(revision, text);
  await f.corpus.removeArtifact(revision);
  await f.corpus.removeArtifact(revision);
  assert.deepEqual(removed, ["item-one", revision.snapshot_key, revision.snapshot_key]);
  assert.equal(await f.corpus.getSnapshot(revision), null);
  for (const changes of [{ snapshot_key: "pre-existing-user-data" }, { index_key: "other.txt" }, { item_id: "../item" }]) {
    await assert.rejects(f.corpus.removeArtifact({ ...revision, ...changes }), { code: "invalid_artifact_removal" });
  }
  f.index.items.list = async () => ({ result: [{ id: "other-item", key: revision.index_key, status: "completed" }] });
  await assert.rejects(f.corpus.removeArtifact(revision), { code: "invalid_artifact_removal" });
  assert.equal(removed.length, 3);
});
