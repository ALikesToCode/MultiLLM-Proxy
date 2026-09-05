import assert from "node:assert/strict";
import test from "node:test";
import { TurnTraceJournal } from "../worker/roleplay/turn-trace.mjs";
import { parseRoutingPolicy, filterRoutingCandidates, rankFastestEligible, parameterReceipt } from "../worker/roleplay/routing-policy.mjs";
import { handleRoleplayOperatorRequest } from "../worker/roleplay/operator-edge.mjs";

test("timeline exposes bounded metadata, never response content", async () => {
  let stored;
  const journal = new TurnTraceJournal({ get: async () => [], put: async (_, rows) => { stored = structuredClone(rows); } });
  await journal.ready;
  const trace = journal.begin();
  trace.phase("connecting");
  trace.progress({ firstReasoningMs: 3, firstContentMs: null, prompt: "private" });
  trace.progress({ firstReasoningMs: 3, firstContentMs: 9 });
  await trace.finish(false, "incomplete_eof");
  assert.deepEqual(stored[0].events.map((event) => event.phase), ["queued", "connecting", "reasoning", "visible", "interrupted"]);
  assert.ok(!JSON.stringify(stored).includes("private"));
  for (let i = 0; i < 50; i++) await journal.begin().finish(true, "complete");
  assert.equal(journal.snapshot().records.length, 30);
});

test("fastest routing crosses provider tiers but rejects stale and cooling samples", () => {
  const now = Date.now();
  const candidates = ["a", "b", "c"].map((provider) => ({ provider, model: "glm-5.3-flash", credentialId: "primary" }));
  const stats = Object.fromEntries(candidates.map((c, i) => [`${c.provider}:${c.model}`, {
    successes: 3, attempts: 3, ewmaTtfbMs: 100, ewmaTokensPerSecond: 10 + i * 100, lastUsedAt: now,
  }]));
  stats["c:glm-5.3-flash"].lastUsedAt = 1;
  assert.equal(rankFastestEligible(candidates, stats, now)[0].provider, "b");
  stats["b:glm-5.3-flash"].cooldownUntil = now + 1000;
  assert.equal(rankFastestEligible(candidates, stats, now)[0].provider, "a");
});

test("pins and subscription-only filters cannot escape their requested boundary", () => {
  const policy = parseRoutingPolicy({ mode: "pinned", provider: "nanogpt", model: "example", billing: "subscription-only", fallback: "none" });
  assert.deepEqual(filterRoutingCandidates([
    { provider: "nanogpt", model: "example", subscriptionOnly: false },
    { provider: "openrouter", model: "example", subscriptionOnly: true },
  ], policy), []);
  assert.throws(() => parseRoutingPolicy({ mode: "pinned" }));
  assert.throws(() => parseRoutingPolicy({ api_key: "never-store" }));
  const receipt = parameterReceipt({ forwarded: { reasoning_effort: "max" }, routing: policy },
    { provider: "nanogpt", model: "z-ai/glm-5.3-flash", family: "glm", billingMode: "subscription" }, {});
  assert.equal(receipt.wireEffort, "xhigh");
  assert.equal(receipt.providerAcknowledged, false);
});

test("operator diagnostics reject roleplay-only credentials without touching session state", async () => {
  const response = await handleRoleplayOperatorRequest(new Request("https://proxy.test/v1/roleplay/control/timeline?session_id=example-session",
    { headers: { Authorization: "Bearer synthetic-roleplay" } }),
    { ROLEPLAY_API_KEY: "synthetic-roleplay", ADMIN_API_KEY: "synthetic-admin" });
  assert.equal(response.status, 401);
});
