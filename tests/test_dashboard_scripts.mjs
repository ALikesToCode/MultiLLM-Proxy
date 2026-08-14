import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const appSource = readFileSync("static/js/app.js", "utf8");
const catalogSource = readFileSync("static/js/auto-route-catalog.js", "utf8");
const editorSource = readFileSync("static/js/auto-routes.js", "utf8");

function browserContext(getElementById = () => null) {
  const document = {
    addEventListener() {},
    createElement() {
      return {};
    },
    getElementById,
  };
  const window = {
    addEventListener() {},
    setTimeout() {},
  };
  return vm.createContext({ console, document, navigator: {}, window });
}

test("catalog registers beside the frozen shared UI helpers", () => {
  const context = browserContext();

  vm.runInContext(appSource, context);
  assert.equal(Object.isFrozen(context.window.MultiLLM), true);

  vm.runInContext(catalogSource, context);
  assert.equal(
    typeof context.window.MultiLLMAutoRoutes.createAutoRouteCatalog,
    "function",
  );
});

test("route editor reports a mixed asset version without throwing", () => {
  const status = {
    classList: { add() {} },
    textContent: "",
  };
  const elements = {
    "operations-dashboard": { dataset: { admin: "true" } },
    "auto-route-panel": {},
    "auto-route-status": status,
  };
  const context = browserContext((id) => elements[id] || null);

  assert.doesNotThrow(() => vm.runInContext(editorSource, context));
  assert.match(status.textContent, /out of date/i);
});
