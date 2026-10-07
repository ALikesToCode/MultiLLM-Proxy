import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync("static/js/cascades.js", "utf8");
class Element {
  children = []; listeners = {}; value = ""; textContent = ""; disabled = false;
  dataset = { endpoint: "/admin/cascades" };
  appendChild(child) { this.children.push(child); }
  replaceChildren() { this.children = []; }
  addEventListener(event, handler) { this.listeners[event] = handler; }
  querySelector() { return this.button; }
}

test("cascade editor loads and saves JSON with CSRF and safe text rendering", async () => {
  const elements = Object.fromEntries(["cascade-panel", "cascade-select", "cascade-config", "cascade-status", "cascade-form"].map(id => [id, new Element()]));
  elements["cascade-form"].button = new Element();
  const calls = [];
  let stored = [];
  const context = vm.createContext({ document: {
    getElementById: id => elements[id], createElement: () => new Element(), querySelector: () => ({ content: "synthetic-csrf" }),
  }, fetch: async (url, options) => {
    calls.push({ url, options });
    if (options.method === "PUT") stored = [JSON.parse(options.body)];
    return { ok: true, json: async () => ({ cascades: stored }) };
  } });
  vm.runInContext(source, context);
  await new Promise(resolve => setImmediate(resolve));
  const config = { name: "cascade:synthetic", tiers: [{ model: "p:cheap" }, { model: "p:strong" }], checks: ["complete"] };
  elements["cascade-config"].value = JSON.stringify(config);
  await elements["cascade-form"].listeners.submit({ preventDefault() {} });
  assert.equal(calls.length, 2);
  assert.equal(calls[1].options.headers["X-CSRFToken"], "synthetic-csrf");
  assert.deepEqual(JSON.parse(calls[1].options.body), config);
  assert.equal(elements["cascade-status"].textContent, "Cascade saved.");
  assert.equal(elements["cascade-select"].children[1].textContent, config.name);
  assert.equal(elements["cascade-form"].button.disabled, false);
  elements["cascade-config"].value = "{bad";
  await elements["cascade-form"].listeners.submit({ preventDefault() {} });
  assert.equal(calls.length, 2);
  assert.notEqual(elements["cascade-status"].textContent, "Cascade saved.");
});

test("cascade editor is harmless outside the administrator page", () => {
  assert.doesNotThrow(() => vm.runInNewContext(source, { document: { getElementById: () => null } }));
});
