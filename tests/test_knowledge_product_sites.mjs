import assert from "node:assert/strict";
import test from "node:test";
import { createArtifact, dropForeignProviderSections, site } from "../worker/knowledge/evidence.mjs";
import { parseProductSites, SITE_LIMIT, PAGE_LIMIT } from "../worker/knowledge/product-sites.mjs";
import { filterProviderSites } from "../worker/knowledge/provider-site-filter.mjs";
import { retrieveKnowledge } from "../worker/knowledge/retrieval.mjs";
import { dispatchKnowledge } from "../worker/knowledge/service.mjs";
import { defaultPolicy, validatePolicy, withProviderDefaults } from "../worker/knowledge/policy.mjs";
import { cacheKey } from "../worker/knowledge/cache.mjs";
import { fixture, manager, principal, request, seedProductSitePages } from "./knowledge_fixture.mjs";

const section = (url, text = "Availability: browser support configured with feature detection.") =>
  `### Availability\nSource: ${url}\n${text}\n--------------------------------`;
const context = text => ({ kind: "derived_context", provider: "mintlify", text });
const registry = sites => ({ product: "codex", sites: Object.fromEntries(sites.map(([host, verified, pinned = false]) =>
  [host, { verified, pinned, first_seen: "2026-10-01T00:00:00Z", last_seen: "2026-10-01T00:00:00Z" }])), blocked: {}, revision: 1 });
const ask = { query: "Which hook events can add context?", product: "codex" };
const run = (f, query = request({ mode: "smart" })) => retrieveKnowledge(f.env, f.authority, principal, query,
  { corpus: f.corpus, cache: f.cache, retrieve: f.retrieve });
const update = (f, input) => f.authority.call("product_sites.update", input);
const get = (f, product = "flask") => f.authority.call("product_sites.get", { product });

async function liveFixture(mode = "observe", sourceEvidence = true) {
  const f = await fixture();
  f.policy.product_sites_mode = mode;
  f.policy.allowed_hosts = ["*"];
  f.policy.providers.mintlify = { ...f.policy.providers.exa };
  await f.storage.put("policy", f.policy);
  const text = section("https://overflow.co/availability/", "Request size limits are configured per route.");
  f.retrieve = async (provider, _intent, { invoke }) => invoke(provider, "lookup", async () => provider === "exa"
    ? { observations: sourceEvidence ? [{ kind: "source_excerpt", provider, url: f.source.url, text: f.text, freshness: "live" }] : [], warnings: [] }
    : { observations: [context(text), { kind: "discovery", provider, url: "https://overflow.co/availability/" }], warnings: [] });
  return f;
}

test("published artifacts learn once and live verification followed by publication cannot double count", async () => {
  const f = await fixture();
  const artifact = await f.published();
  let sites = await get(f);
  assert.equal(sites.sites[site(f.source.url)].verified, 1);
  const jobs = (await f.authority.call("snapshot")).jobs;
  await f.authority.call("job.publish", { id: jobs[0].id, artifact_id: artifact.id });
  await f.authority.call("product_sites.learn", { id: artifact.id });
  assert.equal((await get(f)).sites[site(f.source.url)].verified, 1);
  assert.equal((await get(f)).revision, sites.revision);
  const live = await fixture();
  await run(live, request({ mode: "economy" }));
  sites = await get(live);
  assert.equal(sites.sites[site(live.source.url)].verified, 1);
  await run(live, request({ mode: "economy", freshness: "fresh" }));
  const liveArtifact = [...(await live.storage.list({ prefix: "artifact:" })).values()][0];
  const liveJob = await live.authority.call("job.enqueue", { source_id: liveArtifact.source_id });
  await live.authority.call("job.publish", { id: liveJob.id, artifact_id: liveArtifact.id,
    item_id: "live-item", index_key: liveArtifact.index_key });
  assert.equal((await get(live)).sites[site(live.source.url)].verified, 1);
});

test("unconfirmed manifests do not learn, while retained identity markers survive artifact expiry", async () => {
  const f = await fixture();
  const artifact = await createArtifact(f.source, f.text, "firecrawl");
  await f.authority.call("artifact.save", { artifact });
  assert.deepEqual((await get(f)).sites, {});
  await f.authority.call("product_sites.learn", { id: artifact.id });
  await f.storage.delete(`artifact:${artifact.id}`);
  await f.authority.call("artifact.save", { artifact });
  await f.authority.call("product_sites.learn", { id: artifact.id });
  assert.equal((await get(f)).sites[site(f.source.url)].verified, 1);
  assert.equal(await f.authority.call("product_sites.learn", { id: "missing" }), false);
});

test("learning evicts the weakest oldest unpinned site and retries never inflate eviction counts", async () => {
  const f = await fixture();
  const learned = registry(Array.from({ length: SITE_LIMIT }, (_, i) => [`site${i}.dev`, i < 2 ? 1 : 2]));
  learned.product = "flask";
  learned.sites["site0.dev"].last_seen = "2026-10-01T00:00:00Z";
  learned.sites["site1.dev"].last_seen = "2026-10-02T00:00:00Z";
  learned.sites["site2.dev"].pinned = true;
  await f.storage.put("product-sites:flask", learned);
  await f.published();
  const sites = await get(f);
  assert.equal(Object.keys(sites.sites).length, SITE_LIMIT);
  assert.ok(!sites.sites["site0.dev"]);
  assert.ok(sites.sites["site1.dev"]);
  assert.ok(sites.sites["site2.dev"].pinned);
  assert.equal(sites.sites[site(f.source.url)].verified, 1);
});

test("all-pinned and product storage bounds decline learning without failing publication or retrieval", async () => {
  const f = await fixture();
  await update(f, { product: "flask", pin: Array.from({ length: SITE_LIMIT }, (_, i) => `pin${i}.dev`) });
  await f.published();
  assert.equal(Object.keys((await get(f)).sites).length, SITE_LIMIT);
  assert.ok(!(await get(f)).sites[site(f.source.url)]);
  const products = await fixture();
  for (let i = 0; i < 400; i++) await products.storage.put(`product-sites:product-${i}`, registry([]));
  await products.published();
  assert.deepEqual((await get(products)).sites, {});
  await assert.rejects(update(products, { product: "flask", pin: ["flask.dev"] }), { code: "product_sites_limit" });
});

test("rebuild uses all retained artifacts, resets learned counts and preserves pinned and blocked overrides", async () => {
  const f = await fixture();
  const artifact = await f.published();
  await update(f, { product: "flask", pin: ["docs.pinned.dev"], block: ["overflow.co"], note: "Payment docs" });
  const before = await get(f);
  before.sites[site(f.source.url)].verified = 50;
  before.sites["expired.dev"] = { ...before.sites[site(f.source.url)], verified: 1 };
  await f.storage.put("product-sites:flask", before);
  const rebuilt = await update(f, { product: "flask", rebuild: true });
  assert.equal(rebuilt.sites[site(f.source.url)].verified, 1);
  assert.ok(!rebuilt.sites["expired.dev"]);
  assert.ok(rebuilt.sites["pinned.dev"].pinned);
  assert.equal(rebuilt.sites["pinned.dev"].verified, 0);
  assert.deepEqual(rebuilt.blocked, before.blocked);
  await f.authority.call("product_sites.learn", { id: artifact.id });
  assert.equal((await get(f)).sites[site(f.source.url)].verified, 1);
  assert.equal((await get(f)).revision, rebuilt.revision);
  await update(f, { product: "flask", unpin: ["pinned.dev"], unblock: ["overflow.co"] });
  assert.ok(!(await get(f)).sites["pinned.dev"]);
  assert.deepEqual((await get(f)).blocked, {});
});

test("page identity survives revised content, changed providers and reacquisition and refreshes recency", async () => {
  const f = await fixture();
  const first = await f.published();
  const before = await get(f);
  const now = Date.now() + 1000;
  f.authority.now = () => now;
  const revised = await createArtifact(f.source, `${f.text}\nRevised content.`, "exa");
  assert.notEqual(revised.id, first.id);
  await f.authority.call("artifact.save", { artifact: revised });
  await f.authority.call("product_sites.learn", { id: revised.id });
  const after = await get(f);
  assert.equal(after.sites[site(f.source.url)].verified, 1);
  assert.equal(after.sites[site(f.source.url)].last_seen, new Date(now).toISOString());
  assert.equal(after.revision, before.revision);
  assert.equal((await f.storage.list({ prefix: "product-site-page:" })).size, 1);
});

test("full page identity store evicts least recently seen pages across products and protects zero-count pins", async () => {
  const f = await fixture();
  await get(f); // Initialize the new schema before seeding a full store.
  const other = registry([["old.dev", 1], ["pinned.dev", 1, true], ["recent.dev", PAGE_LIMIT - 2]]);
  other.product = "other";
  for (const entry of Object.values(other.sites)) entry.identity_epoch = 1;
  await f.storage.put("product-sites:other", other);
  await seedProductSitePages(f.storage, Array.from({ length: PAGE_LIMIT }, (_, i) =>
    ({ page_id: `old-${i}`, product: "other",
      site: i === 0 ? "old.dev" : i === 1 ? "pinned.dev" : "recent.dev", identity_epoch: 1,
      first_seen: "2020-01-01T00:00:00Z", last_seen: new Date(i * 1000).toISOString() })));
  await f.storage.put("product-site-page-count", PAGE_LIMIT);
  const result = await run(f);
  assert.equal(result.status, "ok");
  assert.equal((await get(f)).sites[site(f.source.url)].verified, 1);
  assert.ok(!(await get(f, "other")).sites["old.dev"]);
  const another = { id: "another-page", product: "flask", canonical_url: `${f.source.url}other/`, fetched_at: new Date().toISOString() };
  await f.storage.put(`artifact:${another.id}`, another);
  await f.authority.call("product_sites.learn", { id: another.id });
  assert.equal((await get(f, "other")).sites["pinned.dev"].verified, 0);
  assert.ok((await get(f, "other")).sites["pinned.dev"].pinned);
  assert.equal((await f.storage.list({ prefix: "product-site-page:" })).size, PAGE_LIMIT);
  assert.equal(await f.storage.get("product-site-page-count"), PAGE_LIMIT);
});

test("relearning refreshes LRU ordering without incrementing counts", async () => {
  const f = await fixture();
  const artifact = await f.published();
  const pages = await f.storage.list({ prefix: "product-site-page:" });
  const [, identity] = [...pages][0];
  await f.storage.delete(`product-site-lru:${identity.last_seen}:${identity.page_id}`);
  identity.last_seen = "1970-01-01T00:00:00.000Z";
  await seedProductSitePages(f.storage, [identity, ...Array.from({ length: PAGE_LIMIT - 1 }, (_, i) =>
    ({ page_id: `filler-${i}`, product: "flask", site: "unused.dev", identity_epoch: null,
      first_seen: "2020-01-01T00:00:00Z", last_seen: "2020-01-01T00:00:00Z" }))]);
  await f.authority.call("product_sites.learn", { id: artifact.id });
  const newArtifact = { ...artifact, id: "new-page", canonical_url: `${artifact.canonical_url}other/` };
  await f.storage.put(`artifact:${newArtifact.id}`, newArtifact);
  await f.authority.call("product_sites.learn", { id: newArtifact.id });
  assert.equal((await get(f)).sites[site(f.source.url)].verified, 2);
  assert.ok([...(await f.storage.list({ prefix: "product-site-page:" })).values()]
    .some(entry => entry.page_id === identity.page_id));
});

test("rebuild paginates beyond 1000 manifests and deduplicates page revisions", async () => {
  const f = await fixture();
  const artifact = await f.published();
  const manifests = Object.fromEntries(Array.from({ length: 1005 }, (_, i) => [`artifact:scan-${String(i).padStart(5, "0")}`,
    { ...artifact, id: `scan-${i}`, product: i < 1000 ? "other" : "flask", canonical_url: `https://late.dev/page/${i}` }]));
  manifests["artifact:scan-revision"] = { ...artifact, id: "scan-revision" };
  await f.storage.put(manifests);
  const calls = [];
  const list = f.storage.list.bind(f.storage);
  f.storage.list = async options => { if (options.prefix === "artifact:") calls.push(options); return list(options); };
  const rebuilt = await update(f, { product: "flask", rebuild: true });
  assert.equal(rebuilt.sites["late.dev"].verified, 5);
  assert.equal(rebuilt.sites[site(f.source.url)].verified, 1);
  assert.ok(calls.some(options => options.startAfter && options.limit === 1000));
  assert.equal((await f.storage.list({ prefix: "product-site-page:" })).size, 6);
});

test("rebuild rejects a scan exceeding its cap before changing learned history", async () => {
  const f = await fixture();
  await f.published();
  const before = await get(f);
  const list = f.storage.list.bind(f.storage);
  let seen = 0;
  f.storage.list = async options => {
    if (options.prefix !== "artifact:") return list(options);
    assert.ok(options.limit <= 1000);
    return new Map(Array.from({ length: options.limit }, () => [`artifact:large-${String(seen++).padStart(6, "0")}`, {}]));
  };
  await assert.rejects(update(f, { product: "flask", rebuild: true }), { code: "product_sites_limit" });
  assert.equal(seen, 100001);
  f.storage.list = list;
  assert.deepEqual(await get(f), before);
});

test("identity eviction never decrements a site's later incarnation", async () => {
  const f = await fixture();
  await f.published();
  const stored = await f.storage.get("product-sites:flask");
  const host = site(f.source.url);
  stored.sites[host].identity_epoch++;
  stored.sites[host].verified = 1;
  await f.storage.put("product-sites:flask", stored);
  const pages = await f.storage.list({ prefix: "product-site-page:" });
  const [, identity] = [...pages][0];
  await f.storage.delete(`product-site-lru:${identity.last_seen}:${identity.page_id}`);
  identity.last_seen = "1970-01-01T00:00:00Z";
  await seedProductSitePages(f.storage, [identity, ...Array.from({ length: PAGE_LIMIT - 1 }, (_, i) =>
    ({ page_id: `filler-${i}`, product: "flask", site: "unused.dev", identity_epoch: null,
      last_seen: "2020-01-01T00:00:00Z" }))]);
  const artifact = { id: "new-incarnation-page", product: "flask", canonical_url: `${f.source.url}new/` };
  await f.storage.put(`artifact:${artifact.id}`, artifact);
  await f.authority.call("product_sites.learn", { id: artifact.id });
  assert.equal((await get(f)).sites[host].verified, 2);
  assert.ok(!Object.hasOwn((await get(f)).sites[host], "identity_epoch"));
});

test("reading legacy revision identities migrates retained pages and preserves operator overrides", async () => {
  const f = await fixture();
  const artifact = await createArtifact(f.source, f.text, "firecrawl");
  const older = { ...artifact, id: "older-revision" };
  const legacy = registry([[site(f.source.url), 2], ["pinned.dev", 0, true], ["expired.dev", 1]]);
  legacy.product = "flask";
  legacy.blocked["wrong.dev"] = { at: "2020-01-01", note: "Wrong product" };
  await f.storage.put({ "product-sites:flask": legacy, [`artifact:${artifact.id}`]: artifact, "artifact:older-revision": older,
    [`product-site-artifact:${artifact.id}`]: { product: "flask" }, "product-site-artifact:older-revision": { product: "flask" },
    "product-site-artifact-count": 2 });
  const migrated = await get(f);
  assert.equal(migrated.sites[site(f.source.url)].verified, 1);
  assert.ok(migrated.sites["pinned.dev"].pinned);
  assert.ok(!migrated.sites["expired.dev"]);
  assert.deepEqual(migrated.blocked, legacy.blocked);
  assert.equal((await f.storage.list({ prefix: "product-site-artifact:" })).size, 0);
  assert.equal(await f.storage.get("product-site-artifact-count"), undefined);
  assert.equal(await f.storage.get("product-site-page-count"), 1);
  assert.deepEqual(await get(f), migrated);
  await f.authority.call("product_sites.learn", { id: artifact.id });
  assert.equal((await get(f)).sites[site(f.source.url)].verified, 1);
});

test("pin batches preserve earlier and later pins when evicting learned sites", async () => {
  const f = await fixture();
  const learned = registry(Array.from({ length: SITE_LIMIT }, (_, i) => [`site${i}.dev`, 1]));
  await f.storage.put("product-sites:codex", learned);
  const saved = await update(f, { product: "codex", pin: ["new.dev", "site0.dev", "site1.dev"] });
  for (const host of ["new.dev", "site0.dev", "site1.dev"]) assert.ok(saved.sites[host].pinned);
  assert.equal(Object.keys(saved.sites).length, SITE_LIMIT);
});

test("management validates product names, canonical sites, types, conflicting actions and list bounds", async () => {
  assert.equal(parseProductSites({ product: " CSS overflow-clip-margin ", pin: ["developer.mozilla.org"] }, true).product,
    "css overflow-clip-margin");
  assert.deepEqual(parseProductSites({ product: "Codex", pin: ["docs.openai.com", "openai.com"] }, true).pin, ["openai.com"]);
  for (const input of [{}, { product: " " }, { product: "x".repeat(101) }, { product: "a\n" }, { product: 1 },
    { product: "a", unknown: true }, { product: "a", rebuild: "true" }, { product: "a", note: "x".repeat(501) },
    { product: "a", pin: ["UPPER.dev"] }, { product: "a", pin: ["https://openai.com"] },
    { product: "a", pin: ["localhost"] }, { product: "a", pin: ["foo.internal"] }, { product: "a", pin: ["a.dev", "a.dev"] },
    { product: "a", pin: ["a.dev"], unpin: ["docs.a.dev"] }, { product: "a", block: ["a.dev"], unblock: ["a.dev"] },
    { product: "a", block: Array.from({ length: 65 }, (_, i) => `site${i}.dev`) }]) {
    assert.throws(() => parseProductSites(input, true), { code: "invalid_request" });
  }
  const f = await fixture();
  await update(f, { product: "flask", block: Array.from({ length: 64 }, (_, i) => `blocked${i}.dev`) });
  await assert.rejects(update(f, { product: "flask", block: ["more.dev"] }), { code: "product_sites_limit" });
  await update(f, { product: "flask", pin: Array.from({ length: 64 }, (_, i) => `pin${i}.dev`) });
  await assert.rejects(update(f, { product: "flask", pin: ["extra.dev"] }), { code: "product_sites_limit" });
});

test("management dispatcher enforces scope, rejects invalid input and exposes only aggregate status", async () => {
  const f = await fixture();
  const call = (operation, payload, user = manager) => dispatchKnowledge(f.env,
    { version: 1, operation, principal: user, payload }, { authority: f.authority });
  for (const operation of ["product_sites.get", "product_sites.update"]) {
    await assert.rejects(call(operation, { product: "flask" }, principal), { code: "insufficient_scope" });
    await assert.rejects(call(operation, { product: "flask", typo: true }), { code: "invalid_request" });
  }
  const saved = await call("product_sites.update", { product: " Flask ", pin: ["docs.python.org"], note: "Reviewed" });
  assert.deepEqual(await call("product_sites.get", { product: "flask" }), saved);
  assert.ok(saved.sites["python.org"].pinned);
  const status = await call("status", {});
  assert.deepEqual(status.product_sites, { products: 1, sites: 1, blocked: 0, artifact_identities: 0,
    product_limit: 400, artifact_identity_limit: 10000 });
  assert.ok(!JSON.stringify(status.product_sites).includes("python.org"));
});

test("policy defaults to observe and validates only the three documented modes", () => {
  assert.equal(defaultPolicy().product_sites_mode, "observe");
  assert.equal(withProviderDefaults({ providers: {} }).product_sites_mode, "observe");
  const { revision, ...policy } = defaultPolicy();
  for (const mode of ["off", "observe", "enforce"]) assert.equal(validatePolicy({ ...policy, expected_revision: revision,
    product_sites_mode: mode }).product_sites_mode, mode);
  for (const mode of [null, true, "strict", 1]) assert.throws(() => validatePolicy({ ...policy, expected_revision: revision,
    product_sites_mode: mode }), { code: "invalid_policy" });
});

for (const [product, learned, wrong] of [
  ["css overflow-clip-margin", ["developer.mozilla.org", "caniuse.com", "github.com/mdn"], "https://overflow.co/availability"],
  ["codex", ["openai.com", "github.com/openai", "chatgpt.com"], "https://docs.codex.io/wallets"],
]) test(`enforce rejects the real ${product} homonym even with four matching query terms`, () => {
  const query = { product, query: "Availability browser support configured with feature detection?" };
  const known = registry(learned.map(host => [site(`https://${host}`), 1]));
  const items = [context(section(wrong))];
  const evidence = [`https://${learned[0]}/guide`];
  assert.equal(dropForeignProviderSections(items, query, evidence).items.length, 1);
  const filtered = filterProviderSites(items, query, evidence, known, "enforce");
  assert.equal(filtered.items.length, 0);
  assert.deepEqual(filtered.dropped, { mintlify: 1 });
  assert.deepEqual([...filtered.droppedSites], [site(wrong)]);
});

test("enforce keeps learned, pinned and same-answer evidence, but blocked overrides every trust path", () => {
  const known = registry([["learned.dev", 1], ["pinned.dev", 0, true], ["second.dev", 1]]);
  const urls = ["https://learned.dev/hooks", "https://pinned.dev/hooks", "https://answer.dev/hooks", "https://documentation.dev/hooks"];
  const documented = { kind: "provider_documentation", provider: "context7", text: "Source: https://documentation.dev/hooks" };
  const items = [context(urls.map(url => section(url, "Wallets.")).join("")), documented];
  const filtered = filterProviderSites(items, ask, [urls[2]], known, "enforce");
  assert.deepEqual(filtered.items, items);
  known.blocked["answer.dev"] = { at: "2026-10-07", note: "Wrong product" };
  const blocked = filterProviderSites(items, ask, [urls[2]], known, "enforce");
  assert.ok(!blocked.items[0].text.includes("answer.dev"));
  assert.deepEqual(blocked.flagged, [{ provider: "mintlify", site: "answer.dev", reason: "blocked" }]);
});

test("five pages establish one learned site, while pins alone never establish a product", () => {
  const items = [context(section("https://unknown.dev/hooks", "Codex hooks context events."))];
  assert.equal(filterProviderSites(items, ask, [], registry([["learned.dev", 5]]), "enforce").items.length, 0);
  assert.deepEqual(filterProviderSites(items, ask, [], registry([["pinned.dev", 0, true], ["second.dev", 0, true]]), "enforce").items, items);
});

test("off and observe preserve the legacy heuristic; observe flags at most ten enforce decisions", () => {
  const known = registry([["openai.com", 3], ["github.com/openai", 2]]);
  const items = [context(Array.from({ length: 12 }, (_, i) => section(`https://site${i}.dev/hooks`, "Codex hooks context events.")).join(""))];
  known.blocked["site0.dev"] = { at: "2026-10-07", note: "Wrong" };
  const baseline = dropForeignProviderSections(items, ask, ["https://openai.com/hooks"]);
  for (const mode of ["off", "observe"]) {
    const filtered = filterProviderSites(items, ask, ["https://openai.com/hooks"], known, mode);
    assert.deepEqual(filtered.items, baseline.items);
    assert.deepEqual(filtered.dropped, baseline.dropped);
    assert.equal(filtered.flagged.length, mode === "off" ? 0 : 10);
    if (mode === "observe") assert.equal(filtered.flagged[0].reason, "blocked");
  }
});

test("cold-start enforce matches legacy and preserves URL-less sections and unsectioned provider answers", () => {
  const items = [context(section("https://wrong.dev/wallets", "Wallets.") + "An unlocatable explanation.\n--------------------------------"),
    context("Source: https://wrong.dev/wallets Wallet migrations.")];
  const evidence = ["https://openai.com/hooks"];
  for (const known of [null, registry([]), registry([["openai.com", 1]])]) {
    assert.deepEqual(filterProviderSites(items, ask, evidence, known, "enforce").items,
      dropForeignProviderSections(items, ask, evidence).items);
  }
  const known = registry([["openai.com", 5]]);
  const filtered = filterProviderSites(items, ask, evidence, known, "enforce");
  assert.equal(filtered.items.length, 1);
  assert.ok(filtered.items[0].text.includes("unlocatable"));
});

test("retrieval removes wrong discoveries in enforce and keeps status and gaps identical to observe", async () => {
  const f = await liveFixture("observe");
  const existing = registry([["palletsprojects.com", 1], ["python.org", 1]]);
  existing.product = "flask";
  await f.storage.put("product-sites:flask", existing);
  const observed = await run(f);
  assert.equal(observed.provider_context.length, 1);
  assert.deepEqual(observed.provider_sections_flagged, [{ provider: "mintlify", site: "overflow.co", reason: "unverified_site" }]);
  assert.ok(observed.discoveries.some(item => item.url.includes("overflow.co")));
  f.policy.product_sites_mode = "enforce";
  await f.storage.put("policy", f.policy);
  const enforced = await run(f, request({ mode: "smart", freshness: "fresh" }));
  assert.equal(enforced.provider_context.length, 0);
  assert.ok(!enforced.discoveries.some(item => item.url.includes("overflow.co")));
  assert.deepEqual(enforced.provider_sections_dropped, { mintlify: 1 });
  assert.equal(enforced.provider_sections_flagged, undefined);
  assert.deepEqual(enforced.gaps, observed.gaps);
  assert.equal(enforced.status, observed.status);
});

test("removing the last provider section cannot turn partial into insufficient evidence", async () => {
  const f = await liveFixture("enforce", false);
  await update(f, { product: "flask", block: ["overflow.co"] });
  const bundle = await run(f);
  assert.equal(bundle.status, "partial");
  assert.equal(bundle.provider_context.length, 0);
  assert.deepEqual(bundle.gaps.map(gap => gap.code), ["insufficient_evidence"]);
});

test("registry failures never fail evidence retrieval or create coverage gaps", async () => {
  const f = await liveFixture("enforce");
  const originalGet = f.storage.get.bind(f.storage);
  f.storage.get = async key => {
    if (key.startsWith("product-sites:") || key.startsWith("product-site-artifact")) throw new Error("Synthetic unavailable registry");
    return originalGet(key);
  };
  const bundle = await run(f);
  assert.equal(bundle.status, "ok");
  assert.deepEqual(bundle.gaps, []);
  assert.equal(bundle.provider_context.length, 1);
  const published = await f.published();
  assert.equal((await f.authority.call("artifact.get", { id: published.id })).status, "published");
});

test("cache invalidates registry decisions, but count-only learning below a threshold keeps its key", async () => {
  const f = await fixture();
  const base = { policy: f.policy, generation: 1, product_sites: registry([["openai.com", 1]]) };
  const first = await cacheKey(principal, request(), base);
  base.product_sites.sites["openai.com"].verified = 2;
  assert.equal((await cacheKey(principal, request(), base)).url, first.url);
  base.product_sites.sites["openai.com"].verified = 5;
  assert.notEqual((await cacheKey(principal, request(), base)).url, first.url);
  const beforeBlock = (await cacheKey(principal, request(), base)).url;
  base.product_sites.blocked["overflow.co"] = { at: "2026-10-07", note: "Wrong" };
  assert.notEqual((await cacheKey(principal, request(), base)).url, beforeBlock);
  const live = await liveFixture("enforce");
  await run(live);
  assert.equal((await run(live)).path, "cache");
  await update(live, { product: "flask", block: ["overflow.co"] });
  const blocked = await run(live);
  assert.equal(blocked.path, "live");
  assert.equal(blocked.provider_context.length, 0);
});

test("caught atomic registry-write failure cannot inflate counts on a later publication retry", async () => {
  const f = await fixture();
  const put = f.storage.put.bind(f.storage);
  f.storage.put = async (key, value) => {
    if (typeof key !== "string" && Object.keys(key).some(name => name.startsWith("product-sites:"))) throw new Error("Synthetic write failure");
    return put(key, value);
  };
  const artifact = await f.published();
  assert.deepEqual((await get(f)).sites, {});
  f.storage.put = put;
  await f.authority.call("product_sites.learn", { id: artifact.id });
  await f.authority.call("product_sites.learn", { id: artifact.id });
  assert.equal((await get(f)).sites[site(f.source.url)].verified, 1);
});
