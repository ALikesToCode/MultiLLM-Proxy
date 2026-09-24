import assert from "node:assert/strict";
import test from "node:test";
import { api, queryPayload, sourcePayload } from "../static/js/knowledge/api.mjs";
import { policyPayload, renderPolicy } from "../static/js/knowledge/policy.mjs";
import { safeUrl, renderEvidence, renderSources, renderJobs, renderReadiness } from "../static/js/knowledge/render.mjs";
import { costText, executionPayload, renderTools } from "../static/js/knowledge/alexandria.mjs";

class Element {
  constructor(tag = "div") { this.tag = tag; this.children = []; this.dataset = {}; this.value = ""; this.checked = false; }
  get childNodes() { return this.children; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return (this.text || "") + this.children.map((child) => child.textContent).join(""); }
  set innerHTML(_value) { throw new Error("Untrusted HTML insertion"); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ""; this.children = [...children]; }
}

function dom() {
  const nodes = new Map();
  const element = (id) => {
    if (!nodes.has(id)) nodes.set(id, new Element());
    return nodes.get(id);
  };
  globalThis.document = {
    createElement: (tag) => new Element(tag), getElementById: element,
    querySelector: () => ({ content: "synthetic-csrf" }),
  };
  return element;
}

function descendants(element) { return [element, ...element.children.flatMap(descendants)]; }

test("unsafe source URLs cannot become clickable links", () => {
  for (const value of ["javascript:alert(1)", "data:text/html,test", "http://docs.example/", "https://user:pass@docs.example/", "/relative"]) assert.equal(safeUrl(value), null);
  assert.equal(safeUrl("https://docs.example/path?q=v1#part"), "https://docs.example/path?q=v1#part");
});

test("evidence preserves hostile source text as text and distinguishes related versions", () => {
  const element = dom();
  renderEvidence({ status: "partial", path: "live", elapsed_ms: 30, token_count: 12, token_counting_method: "estimate",
    providers_used: ["firecrawl"], gaps: [{ code: "version_unknown", message: "Requested 3.1.3 is not established." }],
    excerpts: [{ text: '<img src=x onerror="alert(1)">', title: "<script>source</script>", url: "javascript:alert(1)", artifact_id: "a1",
      version: { kind: "unknown" }, locator: { start_byte: 0, end_byte: 34 }, target_match: "unverified" }],
    related_evidence: [{ text: "Release 2.0", url: "https://docs.example/v2", version: { kind: "exact", version: "2.0", proof_url: "https://docs.example/v2" } }],
    freshness: { checked_at: "2026-09-23T00:00:00Z" }, usage: [{ confirmed: 1 }] });
  const root = element("knowledge-results");
  assert.match(root.textContent, /<img src=x onerror=/);
  assert.match(root.textContent, /Requested 3.1.3 is not established/);
  assert.match(root.textContent, /Related evidence with unverified target compatibility/);
  assert.match(root.textContent, /UTF-8 bytes 0–34/);
  const links = descendants(root).filter((item) => item.tag === "a");
  assert.ok(links.every((link) => link.href.startsWith("https://") && link.rel === "noopener noreferrer"));
});

test("sources show unestablished coverage and revision-protected action data", () => {
  const element = dom();
  renderSources([{ id: "s1", product: "flask", version: "3.1.3", provider: "firecrawl", url: "https://docs.example/",
    enabled: true, pinned: false, refresh_hours: 24, revision: 4, current_artifact: null }]);
  const root = element("knowledge-source-list");
  assert.match(root.textContent, /version coverage is not established/);
  const disable = descendants(root).find((item) => item.dataset.action === "disable");
  assert.equal(disable.dataset.revision, "4");
  assert.equal(disable.dataset.id, "s1");
  renderSources([]);
  assert.match(root.textContent, /No sources registered/);
});

test("completed jobs cannot expose a cancel action", () => {
  const element = dom();
  renderJobs([{ id: "done", source_id: "s1", status: "completed" }, { id: "queued", source_id: "s1", status: "queued" }]);
  const buttons = descendants(element("knowledge-jobs")).filter((item) => item.tag === "button");
  assert.equal(buttons.length, 1);
  assert.equal(buttons[0].dataset.id, "queued");
});

test("provider configuration never claims live validation", () => {
  const element = dom();
  renderReadiness({ setup: [{ label: "Worker", configured: false, detail: "Connect the service" }],
    providers: [{ id: "firecrawl", label: "Firecrawl", configured: true, credential_env: "FIRECRAWL_API_KEY", capabilities: ["acquisition"] },
      { id: "deepwiki", configured: true, credential_env: null, capabilities: { discovery: true } }] });
  assert.match(element("knowledge-readiness").textContent, /Setup required/);
  assert.match(element("knowledge-providers").textContent, /Credential configured · live connection not checked/);
  assert.match(element("knowledge-providers").textContent, /No provider key required · live connection not checked/);
});

test("form payloads retain exact versions and omit blank optional fields", () => {
  const values = new Map(Object.entries({ query: " Question ", product: "flask", version: "3.1.3", repository: "", mode: "smart", token_budget: "6000", freshness: "fresh" }));
  assert.deepEqual(queryPayload(values), { query: "Question", product: "flask", version: "3.1.3", mode: "smart", token_budget: 6000, freshness: "fresh" });
  const source = sourcePayload(new Map(Object.entries({ url: " https://docs.example/ ", product: "flask", version: "", provider: "exa", refresh_hours: "24", pinned: "on" })));
  assert.equal(source.pinned, true);
  assert.equal(source.url, "https://docs.example/");
  assert.ok(!Object.hasOwn(source, "version"));
});

test("policy serializes all providers with finite numeric fields and unchecked acknowledgements false", () => {
  const values = new Map(Object.entries({ enabled: "on", cache_ttl_seconds: "300", retention_hours: "168", allowed_hosts: "docs.example\nrelease.example" }));
  for (const id of ["context7", "firecrawl", "exa", "mintlify", "deepwiki", "ai_search", "alexandria"]) {
    for (const key of ["limit", "background_limit", "interactive_reserve"]) values.set(`${id}.${key}`, "0");
    values.set(`${id}.units_per_call`, "1");
  }
  const policy = policyPayload(values, "5");
  assert.equal(policy.expected_revision, 5);
  assert.equal(Object.keys(policy.providers).length, 7);
  assert.deepEqual(policy.allowed_hosts, ["docs.example", "release.example"]);
  assert.deepEqual(policy.providers.exa, { enabled: false, hard_limit_confirmed: false, retention_allowed: false,
    limit: 0, background_limit: 0, interactive_reserve: 0, units_per_call: 1 });
});

test("unavailable service disables policy editing", () => {
  const element = dom();
  renderPolicy(null);
  assert.equal(element("knowledge-policy-fields").disabled, true);
});

test("admin transport sends CSRF on mutations without client credentials", async () => {
  dom();
  let call;
  globalThis.fetch = async (url, options) => { call = { url, options }; return Response.json({ id: "s1" }); };
  await api("sources", { method: "POST", body: { product: "flask" } });
  assert.equal(call.url, "/admin/knowledge/sources");
  assert.equal(call.options.headers.get("X-CSRFToken"), "synthetic-csrf");
  assert.equal(call.options.credentials, "same-origin");
  assert.equal(call.options.cache, "no-store");
  assert.equal(call.options.headers.get("Authorization"), null);
});

test("admin transport reports a conflict and never retries automatically", async () => {
  dom();
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return Response.json({ error: { code: "revision_conflict", message: "Reload the current policy." } }, { status: 409 }); };
  await assert.rejects(api("policy", { method: "PUT", body: {} }), /Reload the current policy/);
  assert.equal(calls, 1);
});

test("Alexandria prices and hostile catalogue descriptions render as text", () => {
  const element = dom();
  renderTools([{ quote_id: "q", name: "<script>bad</script>", description: "<img onerror=bad>",
    provider: "particle", capability: "episodes", creditsCost: 15, perRecord: true }]);
  const root = element("alexandria-tools");
  assert.match(root.textContent, /15 credits per record/);
  assert.match(root.textContent, /<script>bad<\/script>/);
  assert.equal(descendants(root).find(item => item.tag === "button").dataset.quoteId, "q");
  assert.equal(costText({ cost: { credits: 0, state: "confirmed" } }), "Cost: 0 Firecrawl credits.");
  assert.match(costText({ cost: { credits: null, state: "unknown" } }), /Cost: unknown/);
  assert.match(costText({ cost: { credits: 40, state: "confirmed" }, reservation_exceeded: true }), /exceeded/);
});

test("Alexandria execution uses only the selected quote and preserves its receipt id", () => {
  const fields = { options: { value: '{"limit":2}' }, request_id: { value: "request-1" },
    reserve_credits: { value: "15" }, accept_variable_cost: { checked: false } };
  const form = { elements: { namedItem: name => fields[name] } };
  assert.deepEqual(executionPayload(form, { quote_id: "q" }), { quote_id: "q", request_id: "request-1",
    options: { limit: 2 }, reserve_credits: 15, accept_variable_cost: false });
  for (const value of ["[]", "null", "bad JSON"]) {
    fields.options.value = value;
    assert.throws(() => executionPayload(form, { quote_id: "q" }));
  }
});
