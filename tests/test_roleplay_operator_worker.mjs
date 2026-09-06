import assert from "node:assert/strict";
import test from "node:test";
import { makeRoleplayEnv, roleplayRequest, withGlobalFetch, completionResponse, handleRoleplayEdgeRequest } from "./helpers/roleplay_fixture.mjs";
import { handleRoleplayOperatorRequest } from "../worker/roleplay/operator-edge.mjs";
import { rankRoleplayCandidates } from "../worker/roleplay/config.mjs";
import { preserveRecovery, recoveryTemplate } from "../worker/roleplay/recovery.mjs";

const turn = (session_id, extra = {}) => roleplayRequest({ session_id, model: "roleplay:glm", stream: false,
  messages: [{ role: "user", content: "Iona meets Rowan at the inn. The letter is blue." }], ...extra });
const operation = (fixture, session, path, body) => handleRoleplayOperatorRequest(new Request(
  `https://proxy.test/v1/roleplay/control/${path}?session_id=${session}&scope=admin`, {
    method: body ? "POST" : "GET", headers: { Authorization: "Bearer admin-roleplay-key" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  }), fixture.env);

test("request-path pins enforce provider, model, billing, and one attempt", async () => {
  const fixture = makeRoleplayEnv({ NANOGPT_API_KEY: "synthetic-nano", ROLEPLAY_NANOGPT_BILLING_MODE: "subscription" });
  let count = 0;
  await withGlobalFetch(async (url, options) => {
    count++;
    assert.match(String(url), /nano-gpt\.com\/api\/subscription/);
    assert.equal(JSON.parse(options.body).model, "z-ai/glm-5.3");
    return new Response('{"error":{"message":"rejected"}}', { status: 429 });
  }, async () => {
    const response = await handleRoleplayEdgeRequest(turn("pin-request-case", { model: "roleplay:auto", memory: { mode: "off" },
      routing: { mode: "pinned", provider: "nanogpt", model: "z-ai/glm-5.3", billing: "subscription-only", fallback: "none" } }), fixture.env);
    assert.equal(response.status, 429);
    assert.deepEqual(await response.json(), { error: { message: "rejected" } });
    await fixture.waitForBackgroundWork();
  });
  assert.equal(count, 1);
  await withGlobalFetch(() => { assert.fail("Ineligible providers must not be called"); }, async () => {
    const response = await handleRoleplayEdgeRequest(turn("no-billing-escape", {
      routing: { mode: "pinned", provider: "opencode", model: "glm-5.3-flash", billing: "subscription-only", fallback: "none" } }), fixture.env);
    assert.equal(response.status, 503);
  });
});

test("quality prefers Flash across providers; provider-priority remains separate", () => {
  const candidates = [
    { provider: "nanogpt", model: "zai-org/glm-5.2", providerRank: 0 },
    { provider: "opencode", model: "glm-5.3-flash", providerRank: 1 },
  ].map((candidate) => ({ ...candidate, modelRank: 0, family: "glm", familyRank: 0, credentialId: "primary", credentialRank: 0 }));
  assert.equal(rankRoleplayCandidates(candidates, {}, "glm", Date.now(), {}, { mode: "quality" })[0].provider, "opencode");
  assert.equal(rankRoleplayCandidates(candidates, {}, "glm")[0].provider, "nanogpt");
});

test("memory uses revisions, rejects busy edits, and branches remain independent", async () => {
  const fixture = makeRoleplayEnv();
  await withGlobalFetch(async () => completionResponse("glm-5.3-flash", "Iona sets the blue letter on the desk."), async () => {
    assert.equal((await handleRoleplayEdgeRequest(turn("memory-source-case"), fixture.env)).status, 200);
    await fixture.waitForBackgroundWork();
  });
  const inspected = await (await operation(fixture, "memory-source-case", "memory", { action: "inspect" })).json();
  assert.ok(!Object.hasOwn(inspected, "retainedMessages"));
  const payload = { action: "update", revision: inspected.revision, summary: "The letter is blue.", pins: ["Iona wears a brass watch."] };
  const updated = await (await operation(fixture, "memory-source-case", "memory", payload)).json();
  assert.notEqual(updated.revision, inspected.revision);
  assert.equal((await operation(fixture, "memory-source-case", "memory", payload)).status, 409);
  const branch = await (await operation(fixture, "memory-source-case", "branch", { label: "Alternate scene", revision: updated.revision, confirm: true })).json();
  assert.ok(branch.session_id.startsWith("branch-"));
  const copied = await (await operation(fixture, branch.session_id, "memory", { action: "inspect", include_context: true })).json();
  assert.ok(copied.retainedMessages.length);
  assert.deepEqual(copied.pins, payload.pins);
  assert.equal((await operation(fixture, branch.session_id, "memory", { action: "update", revision: copied.revision, summary: "Only this branch changes.", pins: [] })).status, 200);
  const original = await (await operation(fixture, "memory-source-case", "memory", { action: "inspect" })).json();
  assert.equal(original.memory.summary, "The letter is blue.");
  const source = [...fixture.storageBySession.values()][0].instance;
  const slot = await source.turnQueue.acquire(new AbortController().signal, {});
  assert.equal((await operation(fixture, "memory-source-case", "memory", { action: "inspect" })).status, 409);
  slot.finish();
});

test("recovery is opt-in, visible-only, bounded, and consumed before new generation", async () => {
  const fixture = makeRoleplayEnv();
  await operation(fixture, "recovery-source-case", "timeline");
  const { storage } = [...fixture.storageBySession.values()][0];
  const messages = [{ role: "user", content: "Synthetic scene" }];
  assert.equal(recoveryTemplate({}, messages), null);
  await preserveRecovery(storage, null, { success: false, visiblePartial: "private" });
  assert.equal(storage.values.has("operator_recovery_v1"), false);
  const template = recoveryTemplate({ recovery_enabled: true, model: "roleplay:glm", max_tokens: 128 }, messages);
  await preserveRecovery(storage, template, { success: false, visiblePartial: "", assistant: "<think>private thought" }, "trace");
  assert.equal(storage.values.get("operator_recovery_v1").partial, "");
  await preserveRecovery(storage, template, { success: false, assistant: "<think>private thought</think>Visible only." }, "trace");
  assert.equal(storage.values.get("operator_recovery_v1").partial, "Visible only.");
  await preserveRecovery(storage, template, { success: false, visiblePartial: "Iona opens the letter.", assistant: "<think>private thought</think>", reason: "incomplete_eof" }, "synthetic-trace");
  const snapshot = await (await operation(fixture, "recovery-source-case", "recovery", { action: "inspect" })).json();
  assert.equal(snapshot.resumableTransport, false);
  assert.ok(!JSON.stringify(snapshot).includes("private thought"));
  assert.equal((await operation(fixture, "recovery-source-case", "recovery", { action: "continue", token: snapshot.token })).status, 409);
  let count = 0;
  await withGlobalFetch(async () => { count++; return completionResponse("glm-5.3-flash", "She reads the address."); }, async () => {
    const result = await operation(fixture, "recovery-source-case", "recovery", { action: "continue", token: snapshot.token, confirm: true });
    assert.equal(result.status, 200);
    assert.match(result.headers.get("X-Roleplay-Session-ID"), /^recovery-/);
    await result.text();
    await fixture.waitForBackgroundWork();
    assert.equal((await operation(fixture, "recovery-source-case", "recovery", { action: "continue", token: snapshot.token, confirm: true })).status, 404);
  });
  assert.equal(count, 1);
  await preserveRecovery(storage, template, { success: false, visiblePartial: "x".repeat(16001) }, "trace");
  const truncated = await (await operation(fixture, "recovery-source-case", "recovery", { action: "inspect" })).json();
  assert.equal(truncated.truncated, true);
  assert.equal((await operation(fixture, "recovery-source-case", "recovery", { action: "continue", token: truncated.token, confirm: true })).status, 400);
});

test("successful actual request produces private timeline metadata", async () => {
  const fixture = makeRoleplayEnv();
  await withGlobalFetch(async () => completionResponse("glm-5.3-flash", "Private story content."), async () => {
    const response = await handleRoleplayEdgeRequest(turn("timeline-request-case"), fixture.env);
    assert.ok(response.headers.get("X-Roleplay-Trace-ID"));
    await response.text();
    await fixture.waitForBackgroundWork();
  });
  const data = await (await operation(fixture, "timeline-request-case", "timeline")).json();
  assert.equal(data.records[0].phase, "completed");
  assert.equal(data.records[0].parameters.providerAcknowledged, false);
  assert.ok(!JSON.stringify(data).includes("Private story content"));
});
