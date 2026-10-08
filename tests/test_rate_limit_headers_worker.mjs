import assert from "node:assert/strict";
import test from "node:test";
import { applyRateLimitAdvice, captureRateLimitAdvice, snapshotHeaders, rateLimitHeadersEnabled } from "../worker/rate-limit-advice.mjs";

const prefix = "X-MultiLLM-RateLimit-";
function admission(snapshot = { limit: 2, remaining: 1, reset: 60 }) {
  return captureRateLimitAdvice({ authenticated: true, shared: true, snapshot });
}

test("malformed flag logs once without its value", () => {
  const warnings = [];
  const logger = { warn(message) { warnings.push(message); } };
  assert.equal(rateLimitHeadersEnabled({ RATE_LIMIT_HEADERS_ENABLED: "private-bad-flag" }, logger), false);
  assert.equal(rateLimitHeadersEnabled({ RATE_LIMIT_HEADERS_ENABLED: "private-bad-flag" }, logger), false);
  assert.equal(warnings.length, 1);
  assert.ok(!warnings[0].includes("private-bad-flag"));
});

test("disabled and raw responses retain identity, bytes and headers", async () => {
  for (const value of [undefined, "", "false", "0", "no", "off", "private-malformed"]) {
    const response = new Response("original", { headers: { "Retry-After": "120" } });
    assert.equal(applyRateLimitAdvice(response, { RATE_LIMIT_HEADERS_ENABLED: value }, admission()), response);
    assert.equal(await response.text(), "original");
  }
  const response = new Response("raw");
  assert.equal(applyRateLimitAdvice(response, { RATE_LIMIT_HEADERS_ENABLED: "true" }, admission(), { managed: false }), response);
});

test("only authenticated shared snapshots yield advice", () => {
  for (const authenticated of [false, undefined, "true"]) {
    assert.equal(captureRateLimitAdvice({ authenticated, shared: true, snapshot: { limit: 2 } }), null);
  }
  assert.equal(captureRateLimitAdvice({ authenticated: true, shared: false, snapshot: { limit: 2 } }), null);
  const response = new Response("ok");
  assert.equal(applyRateLimitAdvice(response, { RATE_LIMIT_HEADERS_ENABLED: "true" }, null), response);
});

test("copied snapshot remains stable and discloses no principal or key", async () => {
  const snapshot = { limit: 2, remaining: 1, reset: 60, principal: "private-principal", key: "private-key" };
  const captured = admission(snapshot);
  snapshot.remaining = 0;
  const source = new Response("stream", { headers: { "RateLimit-Limit": "provider", "X-RateLimit-Remaining": "99" } });
  const response = applyRateLimitAdvice(source, { RATE_LIMIT_HEADERS_ENABLED: "true" }, captured);
  assert.equal(response.headers.get(prefix + "Remaining"), "1");
  assert.equal(response.headers.get(prefix + "Reset"), "60");
  assert.equal(response.headers.get("RateLimit-Limit"), "provider");
  assert.equal(response.headers.get("X-RateLimit-Remaining"), "99");
  assert.ok(!JSON.stringify([...response.headers]).includes("private-"));
  assert.equal(await response.text(), "stream");
});

test("gateway denial has real retry advice but upstream Retry-After survives", () => {
  const captured = captureRateLimitAdvice({ authenticated: true, shared: true,
    snapshot: { limit: 2, remaining: 0, reset: 43 }, denied: true, retryAfter: 43 });
  let response = applyRateLimitAdvice(new Response("denied", { status: 429 }), { RATE_LIMIT_HEADERS_ENABLED: "true" }, captured);
  assert.equal(response.headers.get("Retry-After"), "43");
  response = applyRateLimitAdvice(new Response("provider", { status: 429, headers: { "Retry-After": "upstream-date" } }),
    { RATE_LIMIT_HEADERS_ENABLED: "true" }, captured);
  assert.equal(response.headers.get("Retry-After"), "upstream-date");
  const allowed = applyRateLimitAdvice(new Response("provider", { status: 429 }), { RATE_LIMIT_HEADERS_ENABLED: "true" }, admission());
  assert.equal(allowed.headers.get("Retry-After"), null);
});

test("Flask parity: known zeros mean exhaustion; unknown and unlimited fields are omitted", () => {
  assert.deepEqual(snapshotHeaders({ limit: 2, remaining: 1, reset: 60 }), {
    [prefix + "Limit"]: "2", [prefix + "Remaining"]: "1", [prefix + "Reset"]: "60" });
  assert.deepEqual(snapshotHeaders({ limit: null, remaining: null, reset: null }), {});
  assert.deepEqual(snapshotHeaders({ limit: 0, remaining: 0, reset: 0 }), {});
  assert.deepEqual(snapshotHeaders({ limit: 3, remaining: 0 }), { [prefix + "Limit"]: "3", [prefix + "Remaining"]: "0" });
  for (const bad of [true, "3", Infinity, NaN, -1, 2.5]) assert.deepEqual(snapshotHeaders({ limit: bad }), {});
});



test("invalid optional fields and forged admission objects are omitted", () => {
  for (const snapshot of [
    { limit: 3, remaining: 4, reset: 86401 },
    { limit: 3, remaining: -1, reset: 0 },
    { limit: 3, remaining: true, reset: "60" },
  ]) assert.deepEqual(snapshotHeaders(snapshot), { [prefix + "Limit"]: "3" });
  const response = new Response("original");
  assert.equal(applyRateLimitAdvice(response, { RATE_LIMIT_HEADERS_ENABLED: "true" },
    { snapshot: { limit: 3 }, denied: true, retryAfter: 60 }), response);
});
