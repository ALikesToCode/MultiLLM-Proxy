import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { scanText, redactText, scanPayload, redactPayload } from "../worker/secret-scan.mjs";
const vectors = JSON.parse(readFileSync(new URL("./fixtures/secret_scan_vectors.json", import.meta.url)));
for (const vector of vectors) test(vector.name, () => {
  const text = vector.parts.join(""), findings = scanText(text);
  assert.deepEqual(findings.map(item => item.type), vector.types);
  if (vector.field) assert.deepEqual(scanPayload({ [vector.field]: text }).types, vector.payload_types);
  const redacted = redactText(text, findings);
  assert.deepEqual(scanText(redacted), findings.filter(item => item.confidence === "heuristic"));
  assert.equal(redacted, redactText(text, findings));
});
test("payload modes, bounded paths, Unicode budget and binary leaves", () => {
  const token = vectors[2].parts.join("");
  const value = { messages: [token, token], password: "AbCdEf0123456789", image: "ABcd0123".repeat(100) };
  const [updated, report] = redactPayload(value, { mode: "redact" });
  assert.equal(report.high, 2); assert.equal(report.heuristic, 1);
  assert.equal(updated.messages[0], updated.messages[1]); assert.equal(value.messages[0], token);
  for (const mode of ["block", "observe", "off"]) assert.equal(redactPayload(value, { mode })[0], value);
  assert.equal(scanPayload(value, { max_bytes: 3 }).truncated, true);
  assert.equal(scanPayload({ a: "🙂", b: token }, { max_bytes: 1 }).high, 0);
  assert.equal(scanPayload(Array(25).fill(token)).paths.length, 20);
});
test("one megabyte remains bounded", () => {
  const start = performance.now();
  assert.deepEqual(scanText("A".repeat(1000000)), []);
  assert.ok(performance.now() - start < 1000);
});

test("portable digests match standard SHA-256 vectors", async () => {
  const { secretDigest } = await import("../worker/secret-digest.mjs");
  const { createHash } = await import("node:crypto");
  for (const value of ["", "abc", "🙂".repeat(200), "synthetic".repeat(1000)]) assert.equal(secretDigest(value), createHash("sha256").update(value).digest("hex").slice(0, 6));
});
