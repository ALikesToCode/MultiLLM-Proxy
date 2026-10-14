import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync("static/js/safety-settings.js", "utf8");
const flush = () => new Promise(resolve => setImmediate(resolve));
const defaults = { enabled: false, failure_mode: "allow", revision: 0 };

function page(replies) {
  const ids = ["safety-panel", "safety-form", "safety-controls", "safety-enabled", "safety-failure-mode", "safety-status", "safety-reload"];
  const nodes = new Map(ids.map(id => [id, { disabled: id === "safety-controls", hidden: id === "safety-reload",
    checked: false, value: "allow", textContent: "", dataset: { endpoint: "/admin/safety" }, listeners: {},
    addEventListener(name, listener) { this.listeners[name] = listener; } }]));
  const calls = [];
  const context = vm.createContext({ document: {
    getElementById: id => nodes.get(id), querySelector: () => ({ content: "synthetic-csrf" }),
  }, fetch: async (url, options) => {
    calls.push({ url, options });
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    return { ok: reply.status === 200, status: reply.status, json: async () => reply.body };
  } });
  vm.runInContext(source, context);
  return { nodes, calls, submit: () => nodes.get("safety-form").listeners.submit({ preventDefault() {} }) };
}

test("dashboard loads persisted settings and saves with CSRF and revision", async () => {
  const view = page([{ status: 200, body: { settings: defaults } },
    { status: 200, body: { settings: { enabled: true, failure_mode: "block", revision: 1 } } }]);
  assert.equal(view.nodes.get("safety-controls").disabled, true);
  await flush();
  assert.equal(view.nodes.get("safety-controls").disabled, false);
  assert.equal(view.nodes.get("safety-enabled").checked, false);
  view.nodes.get("safety-enabled").checked = true;
  view.nodes.get("safety-failure-mode").value = "block";
  await view.submit();
  const sent = view.calls[1].options;
  assert.equal(sent.headers["X-CSRFToken"], "synthetic-csrf");
  assert.equal(sent.credentials, "same-origin");
  assert.deepEqual(JSON.parse(sent.body), { enabled: true, failure_mode: "block", revision: 0 });
  assert.equal(view.nodes.get("safety-status").textContent, "Text screening is enabled.");
});

test("failed or conflicting saves preserve visible edits and require explicit reload", async () => {
  for (const failure of [{ status: 409, body: { error: { code: "safety_settings_conflict" } } }, new Error("Network failure")]) {
    const view = page([{ status: 200, body: { settings: defaults } }, failure,
      { status: 200, body: { settings: { enabled: true, failure_mode: "block", revision: 2 } } }]);
    await flush();
    view.nodes.get("safety-enabled").checked = true;
    await view.submit();
    assert.equal(view.nodes.get("safety-enabled").checked, true);
    assert.equal(view.nodes.get("safety-controls").disabled, true);
    assert.equal(view.nodes.get("safety-reload").hidden, false);
    await view.submit();
    assert.equal(view.calls.length, 2, "no blind retry after an uncertain save");
    await view.nodes.get("safety-reload").listeners.click();
    assert.equal(view.nodes.get("safety-controls").disabled, false);
    assert.equal(view.nodes.get("safety-failure-mode").value, "block");
  }
});

test("unavailable initial settings keep controls disabled until reload succeeds", async () => {
  const view = page([{ status: 503, body: {} }, { status: 200, body: { settings: defaults } }]);
  await flush();
  assert.equal(view.nodes.get("safety-controls").disabled, true);
  assert.equal(view.nodes.get("safety-reload").hidden, false);
  await view.nodes.get("safety-reload").listeners.click();
  assert.equal(view.nodes.get("safety-controls").disabled, false);
});
