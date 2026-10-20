import assert from "node:assert/strict";
import test from "node:test";
import { retrieveKnowledge } from "../worker/knowledge/retrieval.mjs";
import { fixture, principal, request } from "./knowledge_fixture.mjs";

for (const outcome of ["stalled", "slow", "failing"]) {
  test(`${outcome} optional learning preserves the answer within its 250 ms wait`, async t => {
    const f = await fixture();
    const originalCall = f.authority.call.bind(f.authority);
    const originalTimeout = AbortSignal.timeout.bind(AbortSignal);
    let latestTimeout, learningTimeout, learningStarted, learningSettled = false, timer;
    t.mock.method(AbortSignal, "timeout", milliseconds => {
      const signal = originalTimeout(milliseconds);
      latestTimeout = { milliseconds, signal };
      return signal;
    });
    f.authority.call = (operation, payload) => {
      if (operation !== "product_sites.learn") return originalCall(operation, payload);
      learningStarted = performance.now();
      learningTimeout = latestTimeout;
      return new Promise((resolve, reject) => {
        // Keep the event loop alive for AbortSignal's unreferenced timeout as well.
        timer = setTimeout(() => {
          if (outcome === "stalled") return;
          learningSettled = true;
          if (outcome === "failing") reject(new Error("Synthetic learning failure"));
          else resolve({ learned: true });
        }, outcome === "failing" ? 25 : 1000);
      });
    };
    try {
      const result = await retrieveKnowledge(f.env, f.authority, principal, request(),
        { corpus: f.corpus, cache: f.cache, retrieve: f.retrieve });
      const elapsed = performance.now() - learningStarted;
      assert.equal(learningTimeout.milliseconds, 250, "learning owns an exact 250 ms timeout");
      assert.equal(result.status, "ok");
      assert.deepEqual(result.gaps, []);
      assert.equal(result.excerpts.length, 1);
      assert.equal(result.excerpts[0].text, f.text);
      // The timer budget is exact; allow 50 ms for scheduling and answer packing.
      assert.ok(elapsed <= 300, `learning delayed the answer by ${elapsed.toFixed(1)} ms`);
      if (outcome === "failing") {
        assert.equal(learningSettled, true);
        assert.equal(learningTimeout.signal.aborted, false);
      } else {
        assert.equal(learningSettled, false, "the answer does not wait for learning to finish");
        assert.equal(learningTimeout.signal.aborted, true);
        assert.ok(elapsed >= 225, "the real timeout released the answer");
      }
    } finally {
      clearTimeout(timer);
    }
  });
}
