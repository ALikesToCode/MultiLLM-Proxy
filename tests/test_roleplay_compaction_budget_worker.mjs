import assert from "node:assert/strict";
import test from "node:test";
import { compactionOutputBudget, prepareCompactionCandidates } from "../worker/roleplay/compaction-budget.mjs";

const settings = { compactionMaxTokens: 1200, contextSafetyTokens: 1024 };
const glm = { provider: "opencode", family: "glm", model: "glm-5.3-flash", contextWindow: 262144, maxOutputTokens: 131072 };

test("Go compaction reserves the minimum valid thinking and answer budget", () => {
  const [candidate] = prepareCompactionCandidates([glm], 4000, settings);
  assert.equal(candidate.resolvedMaxOutputTokens, 2048);
  assert.equal(compactionOutputBudget(glm, { ...settings, compactionMaxTokens: 3072 }), 3072);
});

test("other providers retain their configured summary budget", () => {
  assert.equal(compactionOutputBudget({ ...glm, provider: "nanogpt" }, settings), 1200);
  assert.equal(compactionOutputBudget({ ...glm, family: "kimi" }, settings), 1200);
});

test("compaction never exceeds provider context or output capacity to satisfy its floor", () => {
  assert.deepEqual(prepareCompactionCandidates([{ ...glm, contextWindow: 6000 }], 4000, settings), []);
  assert.deepEqual(prepareCompactionCandidates([{ ...glm, maxOutputTokens: 1200 }], 1000, settings), []);
});
