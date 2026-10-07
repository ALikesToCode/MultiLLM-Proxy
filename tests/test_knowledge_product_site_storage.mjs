import assert from "node:assert/strict";
import test from "node:test";
import { fixture, seedProductSitePages } from "./knowledge_fixture.mjs";
import { PAGE_LIMIT } from "../worker/knowledge/product-sites.mjs";
import { lruKey, pageKey } from "../worker/knowledge/product-site-identities.mjs";

test("learning and rebuild finish on the first partial storage page", async () => {
  const f = await fixture();
  const artifact = await f.published();
  const list = f.storage.list.bind(f.storage);
  const calls = new Map();
  f.storage.list = async ({ prefix }) => {
    calls.set(prefix, (calls.get(prefix) ?? 0) + 1);
    assert.ok(calls.get(prefix) <= 1, "a partial page terminates that scan");
    return list({ prefix });
  };
  await f.authority.call("product_sites.learn", { id: artifact.id });
  calls.clear();
  const rebuilt = await f.authority.call("product_sites.update", { product: "flask", rebuild: true });
  assert.equal(rebuilt.sites["palletsprojects.com"].verified, 1);
});

test("steady-state learning has bounded reads at 10 and PAGE_LIMIT identities", async () => {
  for (const size of [10, PAGE_LIMIT]) {
    const f = await fixture();
    const artifact = await f.published();
    const identities = [...(await f.storage.list({ prefix: "product-site-page:" })).values()];
    await seedProductSitePages(f.storage, Array.from({ length: size - 1 }, (_, i) => ({
      page_id: `filler-${i}`, product: "flask", site: "filler.dev", identity_epoch: null,
      first_seen: "2020-01-01T00:00:00.000Z", last_seen: new Date(i * 1000).toISOString(),
    })));
    const get = f.storage.get.bind(f.storage);
    const list = f.storage.list.bind(f.storage);
    let reads = 0;
    const lists = [];
    f.storage.get = async key => { reads++; return get(key); };
    f.storage.list = async options => {
      lists.push(options);
      assert.equal(options.prefix, "product-site-lru:", "learning never scans identity records");
      assert.equal(options.limit, 1);
      return list(options);
    };
    f.authority.now = () => Date.parse("2030-01-01T00:00:00.000Z");
    await f.authority.call("product_sites.learn", { id: artifact.id });
    assert.equal(reads, 4, `refresh reads are constant at ${size} pages`);
    assert.equal(lists.length, 0);
    const refreshed = await get(pageKey(identities[0].page_id));
    assert.equal(await get(lruKey(identities[0])), undefined);
    assert.equal(await get(lruKey(refreshed)), refreshed.page_id);
    const another = { ...artifact, id: "new-page", canonical_url: `${artifact.canonical_url}new/` };
    await f.storage.put(`artifact:${another.id}`, another);
    reads = 0;
    await f.authority.call("product_sites.learn", { id: another.id });
    assert.equal(reads, size === PAGE_LIMIT ? 6 : 5);
    assert.equal(lists.length, size === PAGE_LIMIT ? 1 : 0);
    assert.equal(await get("product-site-page-count"), Math.min(PAGE_LIMIT, size + 1));
    assert.ok(await get(pageKey(refreshed.page_id)), "refreshed page survives eviction");
    if (size === PAGE_LIMIT) {
      assert.equal(await get(pageKey("filler-0")), undefined);
      assert.equal(await get("product-site-lru:1970-01-01T00:00:00.000Z:filler-0"), undefined);
    }
  }
});

test("schema-2 slots migrate once in bounded batches with exact timestamps and epochs", async () => {
  const f = await fixture();
  const identities = Array.from({ length: 1005 }, (_, i) => ({ page_id: `page-${i}`,
    product: "flask", site: "palletsprojects.com", first_seen: "2019-01-01T00:00:00.000Z",
    last_seen: new Date(i * 1000).toISOString(), identity_epoch: i % 2 ? 17 : null }));
  const registry = { product: "flask", sites: { "palletsprojects.com": {
    verified: 502, first_seen: identities[0].first_seen, last_seen: identities.at(-1).last_seen,
    pinned: true, identity_epoch: 17 } }, blocked: { "wrong.dev": { at: "2020", note: "Wrong product" } }, revision: 18 };
  await f.storage.put({ "product-site-page-schema": 2, "product-site-page-count": identities.length,
    "product-sites:flask": registry, ...Object.fromEntries(identities.map((entry, i) =>
      [`product-site-page:${String(i).padStart(5, "0")}`, entry])) });
  const put = f.storage.put.bind(f.storage);
  const remove = f.storage.delete.bind(f.storage);
  const list = f.storage.list.bind(f.storage);
  let scans = 0;
  f.storage.put = async (key, value) => {
    if (typeof key !== "string") assert.ok(Object.keys(key).length <= 128);
    return put(key, value);
  };
  f.storage.delete = async keys => { assert.ok(keys.length <= 128); return remove(keys); };
  f.storage.list = async options => {
    assert.equal(options.prefix, "product-site-page:");
    assert.ok(options.limit <= 1000);
    scans++;
    return list(options);
  };
  await f.authority.call("product_sites.get", { product: "flask" });
  assert.equal(scans, 2);
  assert.equal(await f.storage.get("product-site-page-schema"), 3);
  assert.equal(await f.storage.get("product-site-page-count"), identities.length);
  assert.deepEqual(await f.storage.get("product-sites:flask"), registry);
  for (const [i, identity] of identities.entries()) {
    assert.equal(await f.storage.get(`product-site-page:${String(i).padStart(5, "0")}`), undefined);
    assert.deepEqual(await f.storage.get(pageKey(identity.page_id)), identity);
    assert.equal(await f.storage.get(lruKey(identity)), identity.page_id);
  }
  await f.authority.call("product_sites.get", { product: "flask" });
  assert.equal(scans, 2, "schema marker prevents a second scan");
  f.storage.list = list;
  const oldest = [...await f.storage.list({ prefix: "product-site-lru:", limit: 1 })][0];
  assert.equal(oldest[1], "page-0");
});

test("rebuild writes only current page-id records and recency entries", async () => {
  const f = await fixture();
  const artifact = await f.published();
  const [identity] = [...(await f.storage.list({ prefix: "product-site-page:" })).values()];
  f.authority.now = () => Date.now() + 10000;
  await f.authority.call("product_sites.learn", { id: artifact.id });
  const refreshed = await f.storage.get(pageKey(identity.page_id));
  await f.authority.call("product_sites.update", { product: "flask", rebuild: true });
  const [rebuilt] = [...(await f.storage.list({ prefix: "product-site-page:" })).values()];
  const indexes = await f.storage.list({ prefix: "product-site-lru:" });
  assert.equal(indexes.size, 1);
  assert.equal(indexes.get(lruKey(rebuilt)), rebuilt.page_id);
  assert.equal(await f.storage.get(lruKey(refreshed)), undefined);
  assert.deepEqual(await f.storage.get(pageKey(rebuilt.page_id)), rebuilt);
});

test("rebuild computes identities from each manifest page before listing the next", async () => {
  const f = await fixture();
  const artifact = await f.published();
  const list = f.storage.list.bind(f.storage);
  let processed = 0;
  let returned = 0;
  let pages = 0;
  f.storage.list = async options => {
    if (options.prefix !== "artifact:") return list(options);
    assert.equal(processed, returned, "previous raw manifests were consumed before the next page");
    const size = pages++ === 0 ? 1000 : 5;
    const manifests = new Map(Array.from({ length: size }, (_, i) => {
      const entry = { ...artifact, id: `manifest-${returned + i}` };
      Object.defineProperty(entry, "product", { get() { processed++; return "other"; } });
      return [`artifact:manifest-${String(returned + i).padStart(5, "0")}`, entry];
    }));
    returned += size;
    return manifests;
  };
  await f.authority.call("product_sites.update", { product: "flask", rebuild: true });
  assert.equal(pages, 2);
  assert.equal(processed, 1005);
});
