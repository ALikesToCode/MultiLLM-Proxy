import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const appSource = readFileSync("static/js/app.js", "utf8");
const catalogSource = readFileSync("static/js/auto-route-catalog.js", "utf8");
const editorSource = readFileSync("static/js/auto-routes.js", "utf8");
const openrouterSource = readFileSync("static/js/openrouter.js", "utf8");
const dashboardSource = readFileSync("static/js/dashboard.js", "utf8");

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

class FakeElement {
  children = [];
  listeners = {};
  dataset = {};
  style = {};
  classList = { toggle() {}, add() {} };
  text = '';
  value = '';
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren() { this.children = []; this.text = ''; }
  set textContent(value) { this.text = value; this.children = []; }
  get textContent() { return this.text + this.children.map((child) => child.textContent).join(''); }
  addEventListener(event, listener) { this.listeners[event] = listener; }
  setAttribute() {}
}

function labFixture(chatResponse) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  element('openrouter-lab').dataset.admin = 'true';
  element('model-input').value = 'test-model';
  element('prompt-input').value = 'Synthetic prompt';
  element('streaming-toggle').checked = true;
  const context = vm.createContext({
    console, Headers, AbortController, TextDecoder,
    document: {
      getElementById: element,
      querySelector: () => null,
      querySelectorAll: () => [],
      createElement: () => new FakeElement(),
      createTextNode(text) {
        return { textContent: text, appendData(value) { this.textContent += value; } };
      },
    },
    window: {
      addEventListener() {},
      requestAnimationFrame: (callback) => setTimeout(callback, 1),
      cancelAnimationFrame: clearTimeout,
    },
    fetch: async (url, options) => url.includes('credits')
      ? new Response('{"data":{"usage":0,"limit":1}}') : chatResponse(options),
  });
  vm.runInContext(openrouterSource, context);
  return { element, run: () => element('test-button').listeners.click() };
}

const streamContent = 'data: {"choices":[{"delta":{"content":"Preserved partial reply."}}]}\n\n';

test("lab preserves partial output on premature EOF and restores its controls", async () => {
  const fixture = labFixture(() => new Response(streamContent));
  await fixture.run();
  assert.match(fixture.element('response-area').textContent, /Preserved partial reply/);
  assert.match(fixture.element('response-area').textContent, /ended before completion/);
  assert.equal(fixture.element('test-button').disabled, false);
  assert.equal(fixture.element('stop-button').disabled, true);
});

test("lab surfaces in-band errors instead of swallowing them", async () => {
  const fixture = labFixture(() => new Response(streamContent +
    'data: {"error":{"message":"Provider timed out"}}\n\n'));
  await fixture.run();
  assert.match(fixture.element('response-area').textContent, /Preserved partial reply.*Provider timed out/s);
});

test("lab stop cancels the upstream reader and preserves received text", async () => {
  let cancelled = false;
  const fixture = labFixture(() => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode(streamContent)); },
    cancel() { cancelled = true; },
  })));
  const running = fixture.run();
  await new Promise((resolve) => setTimeout(resolve, 10));
  fixture.element('stop-button').listeners.click();
  await running;
  assert.equal(cancelled, true);
  assert.match(fixture.element('response-area').textContent, /Preserved partial reply.*Stopped/s);
});

test("lab cancels a body after DONE without waiting for upstream EOF", async () => {
  let cancelled = false;
  const fixture = labFixture(() => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new TextEncoder().encode(streamContent + 'data: [DONE]\n\n')); },
    cancel() { cancelled = true; },
  })));
  await fixture.run();
  assert.equal(cancelled, true);
  assert.equal(fixture.element('response-area').textContent, 'Preserved partial reply.');
});

test("clipboard rejection reports failure and removes the temporary textarea", async () => {
  let listener;
  let removed = false;
  const region = new FakeElement();
  const context = browserContext(() => region);
  context.document.addEventListener = (_event, callback) => { listener = callback; };
  context.document.body = new FakeElement();
  context.document.execCommand = () => false;
  context.document.createElement = () => Object.assign(new FakeElement(), {
    select() {}, remove() { removed = true; },
  });
  vm.runInContext(appSource, context);
  context.initializeCopyButtons();
  await listener({ target: { closest: () => ({ getAttribute: () => 'Synthetic text' }) } });
  assert.equal(removed, true);
  assert.match(region.textContent, /Could not copy/);
  assert.doesNotMatch(region.textContent, /Copied to clipboard/);
});

function dashboardFixture(fetch) {
  const status = new FakeElement();
  const refresh = new FakeElement();
  const metric = new FakeElement();
  metric.dataset.metric = 'total-requests';
  const elements = {
    'operations-dashboard': { dataset: { admin: 'true', statusSnapshot: '/snapshot', requestLog: '/requests' } },
    'dashboard-initial-state': { textContent: '{}' },
    'stream-state': status,
    'refresh-requests': refresh,
  };
  const timers = new Map();
  const listeners = {};
  let nextTimer = 0;
  const context = browserContext((id) => elements[id] || null);
  Object.assign(context, { AbortController, fetch });
  Object.assign(context.document, {
    hidden: false,
    querySelectorAll: () => [metric],
    addEventListener: (event, callback) => { listeners[event] = callback; },
  });
  Object.assign(context.window, {
    setTimeout(callback, delay) { timers.set(++nextTimer, { callback, delay }); return nextTimer; },
    clearTimeout: (id) => timers.delete(id),
    setInterval() {},
    addEventListener: (event, callback) => { listeners[event] = callback; },
    EventSource() { throw new Error('Dashboard must not occupy a streaming connection'); },
  });
  vm.runInContext(dashboardSource, context);
  return { context, status, refresh, metric, timers, listeners };
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

test('dashboard polling works without EventSource and never overlaps requests', async () => {
  const calls = [];
  const fixture = dashboardFixture((url, options) => new Promise((resolve) => calls.push({ url, options, resolve })));
  fixture.listeners.visibilitychange();
  fixture.listeners.pageshow();
  fixture.refresh.listeners.click();
  assert.equal(calls.length, 2);
  assert.equal(calls[0].options.cache, 'no-store');
  calls[0].resolve(new Response('{"stats":{"total_requests":42}}'));
  calls[1].resolve(new Response('{"requests":[]}'));
  await settle();
  assert.equal(fixture.metric.textContent, '42');
  assert.equal(fixture.status.textContent, 'Live updates');
  assert.deepEqual([...fixture.timers.values()].map((timer) => timer.delay).sort(), [10000, 30000]);
});

test('dashboard pauses hidden tabs, aborts requests and resumes after page restore', async () => {
  const calls = [];
  const fixture = dashboardFixture((_url, { signal }) => new Promise((_resolve, reject) => {
    calls.push(signal);
    signal.addEventListener('abort', () => reject(new Error('Aborted')));
  }));
  fixture.context.document.hidden = true;
  fixture.listeners.visibilitychange();
  await settle();
  assert.ok(calls.every((signal) => signal.aborted));
  assert.equal(fixture.timers.size, 0);
  assert.equal(fixture.status.textContent, 'Paused');
  fixture.listeners.pagehide();
  fixture.context.document.hidden = false;
  fixture.listeners.visibilitychange();
  assert.equal(calls.length, 2);
  fixture.listeners.pageshow();
  assert.equal(calls.length, 4);
  fixture.listeners.pagehide();
  await settle();
});

test('dashboard aborts a stalled snapshot and schedules a bounded retry', async () => {
  const fixture = dashboardFixture((url, { signal }) => url === '/requests'
    ? Promise.resolve(new Response('{"requests":[]}'))
    : new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('Deadline')))));
  await settle();
  [...fixture.timers.values()].find((timer) => timer.delay === 10000).callback();
  await settle();
  assert.equal(fixture.status.textContent, 'Refresh failed · retrying');
  assert.equal(fixture.timers.size, 2);
});
