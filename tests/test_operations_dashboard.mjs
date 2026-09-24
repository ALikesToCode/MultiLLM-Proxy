import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const dashboardSource = readFileSync("static/js/dashboard.js", "utf8");
const explorerSource = readFileSync("static/js/request-explorer.js", "utf8");

class Node {
  constructor(tag = "div") {
    Object.assign(this, { tag, children: [], dataset: {}, attributes: {}, listeners: {}, style: {}, hidden: false,
      value: "", text: "", className: "", options: [{ value: "" }], classes: new Set() });
    this.classList = { add: (name) => this.classes.add(name), toggle() {} };
  }
  append(...children) { this.children.push(...children); }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = [...children]; this.text = ""; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map((child) => child.textContent).join(""); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(event, listener) { this.listeners[event] = listener; }
  querySelector(tag) { return this.children.find((child) => child.tag === tag) ?? null; }
  add(option) { this.options.push(option); }
}

function emptyState() {
  const node = new Node();
  node.append(new Node("strong"), new Node("p"));
  return node;
}

function page(ids, initialState) {
  const elements = new Map(ids.map((id) => [id, id === "request-log-empty" ? emptyState() : new Node()]));
  elements.set("operations-dashboard", Object.assign(new Node(), {
    dataset: { admin: "true", statusSnapshot: "/snapshot", requestLog: "/requests" },
  }));
  elements.set("dashboard-initial-state", Object.assign(new Node(), { textContent: JSON.stringify(initialState ?? {}) }));
  const context = vm.createContext({
    console, AbortController, Option: class { constructor(text, value) { Object.assign(this, { text, value }); } },
    fetch: () => new Promise(() => {}),
    document: {
      hidden: false,
      getElementById: (id) => elements.get(id) ?? null,
      createElement: (tag) => new Node(tag),
      querySelectorAll: () => [],
      addEventListener() {},
    },
    window: { setTimeout: () => 0, clearTimeout() {}, setInterval() {}, addEventListener() {} },
  });
  return { context, element: (id) => elements.get(id) };
}

const PROVIDERS = {
  openrouter: { name: "OPENROUTER", is_configured: true, requests_24h: 10, success_rate: 90, p95_latency: 800,
    last_request_at: new Date().toISOString(), circuit: { state: "closed" } },
  groq: { name: "GROQ", is_configured: true, requests_24h: 4, success_rate: 0, p95_latency: 300,
    last_request_at: new Date().toISOString(), circuit: { state: "open" } },
  "kimi-code": { name: "KIMI-CODE", is_configured: true, requests_24h: 0, success_rate: 0, p95_latency: 0,
    last_request_at: null, circuit: { mode: "bypassed", state: "closed" } },
  azure: { name: "AZURE", is_configured: false, requests_24h: 0, success_rate: 0, p95_latency: 0, circuit: { state: "closed" } },
};

test("provider health separates configuration from traffic evidence without inventing zeros", () => {
  const fixture = page(["provider-health-body", "provider-health-empty", "unconfigured-providers", "unconfigured-list",
    "unconfigured-count", "traffic-chart", "traffic-summary"], { providers: PROVIDERS, stats: { traffic_series: [] } });
  vm.runInContext(dashboardSource, fixture.context);

  const rows = fixture.element("provider-health-body").children;
  assert.equal(rows.length, 3, "unconfigured providers stay out of the matrix");
  const text = (name) => rows.find((row) => row.textContent.includes(name)).textContent;
  assert.match(text("OPENROUTER"), /recent success/);
  assert.match(text("GROQ"), /failing/);
  assert.match(text("KIMI-CODE"), /no traffic yet.*passthrough/);
  assert.doesNotMatch(text("KIMI-CODE"), /0\.0%|0ms/);
  assert.equal(fixture.element("unconfigured-count").textContent, "1");
  assert.equal(fixture.element("unconfigured-list").textContent, "AZURE");
  assert.equal(fixture.element("provider-health-empty").hidden, true);
  assert.equal(fixture.element("traffic-summary").textContent, "No requests in the last 24 hours.");
});

function explorerFixture() {
  const fixture = page(["request-log-body", "request-log-empty", "request-search", "request-provider-filter", "request-status-filter"]);
  vm.runInContext(explorerSource, fixture.context);
  const cell = (value) => Object.assign(new Node("td"), { textContent: value });
  const explorer = fixture.context.window.MultiLLMRequestExplorer.createRequestExplorer({
    cells: { text: cell, pill: cell, circuitClass: () => "tone-neutral" },
    format: { latency: (value) => `${value}ms`, cost: (value) => `$${value}` },
  });
  const empty = fixture.element("request-log-empty");
  return { ...fixture, explorer, message: () => empty.hidden ? null : empty.querySelector("strong").textContent };
}

test("request explorer distinguishes failure, empty, filtered and restricted states", () => {
  const fixture = explorerFixture();
  fixture.explorer.showFailure();
  assert.equal(fixture.message(), "Request records could not be loaded");

  fixture.explorer.setRecords([]);
  assert.equal(fixture.message(), "No requests recorded yet");

  fixture.explorer.setRecords([
    { provider: "openrouter", status_code: 200, request_id: "req-a", actual_cost: 0.002 },
    { provider: "groq", status_code: 429, request_id: "req-b", estimated_cost: 0.001 },
  ]);
  assert.equal(fixture.message(), null);
  fixture.element("request-status-filter").value = "error";
  fixture.element("request-status-filter").listeners.change();
  const rows = fixture.element("request-log-body").children;
  assert.equal(rows.length, 1);
  assert.match(rows[0].textContent, /req-b.*≈ \$0\.001/);

  fixture.element("request-search").value = "no-such-request";
  fixture.element("request-search").listeners.input();
  assert.equal(fixture.element("request-log-body").children.length, 0);
  assert.equal(fixture.message(), "No records match these filters");

  fixture.explorer.showFailure();
  assert.equal(fixture.message(), "No records match these filters", "loaded records are not replaced by a failure notice");
  fixture.explorer.showRestricted();
  assert.equal(fixture.message(), "Administrator access required");
});

test("provider filter options are added once from the provider keys", () => {
  const fixture = explorerFixture();
  fixture.explorer.populateProviders(["groq", "openrouter"]);
  fixture.explorer.populateProviders(["azure"]);
  assert.deepEqual(fixture.element("request-provider-filter").options.map((option) => option.value), ["", "groq", "openrouter"]);
});

test("model catalog lists models from configured providers first and keeps catalog order within groups", () => {
  const catalogSource = readFileSync("static/js/auto-route-catalog.js", "utf8");
  const fixture = page(["auto-route-provider-count", "auto-route-provider-list", "auto-route-catalog-count",
    "auto-route-catalog-search", "auto-route-catalog-provider", "refresh-auto-route-catalog",
    "auto-route-catalog-status", "auto-route-model-catalog", "auto-route-catalog-empty"]);
  vm.runInContext(catalogSource, fixture.context);
  const models = [
    { id: "aihubmix:free-a", provider: "aihubmix", configured: false },
    { id: "nanogpt:glm-5.2", provider: "nanogpt", configured: true },
    { id: "aihubmix:free-b", provider: "aihubmix", configured: false },
    { id: "opencode:glm-5.3-flash", provider: "opencode", configured: true },
  ];
  const catalog = fixture.context.window.MultiLLMAutoRoutes.createAutoRouteCatalog({
    getState: () => ({ candidates: [], modelCatalog: models, providers: [] }),
    onAddModel() {}, onRefresh() {},
  });
  catalog.renderModels();
  const ids = fixture.element("auto-route-model-catalog").children.map((item) => item.children[0].children[0].textContent);
  assert.deepEqual(ids, ["nanogpt:glm-5.2", "opencode:glm-5.3-flash", "aihubmix:free-a", "aihubmix:free-b"]);
});

test("request explorer pages long logs and resets paging when filters change", () => {
  const fixture = page(["request-log-body", "request-log-empty", "request-search", "request-provider-filter",
    "request-status-filter", "request-log-paging", "request-log-summary", "request-log-more"]);
  vm.runInContext(explorerSource, fixture.context);
  const cell = (value) => Object.assign(new Node("td"), { textContent: value });
  const explorer = fixture.context.window.MultiLLMRequestExplorer.createRequestExplorer({
    cells: { text: cell, pill: cell, circuitClass: () => "tone-neutral" },
    format: { latency: (value) => `${value}ms`, cost: (value) => `$${value}` },
  });
  explorer.setRecords(Array.from({ length: 60 }, (_, index) => ({ provider: "groq", status_code: 200, request_id: `req-${index}` })));
  assert.equal(fixture.element("request-log-body").children.length, 25);
  assert.equal(fixture.element("request-log-summary").textContent, "Showing 25 of 60 records");
  fixture.element("request-log-more").listeners.click();
  fixture.element("request-log-more").listeners.click();
  assert.equal(fixture.element("request-log-body").children.length, 60);
  assert.equal(fixture.element("request-log-more").hidden, true);
  fixture.element("request-search").value = "req-1";
  fixture.element("request-search").listeners.input();
  assert.equal(fixture.element("request-log-summary").textContent, "Showing 11 of 11 records");
});
