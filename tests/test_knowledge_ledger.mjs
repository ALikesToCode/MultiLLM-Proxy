import assert from "node:assert/strict";
import test from "node:test";
import { KnowledgeAuthority } from "../worker/knowledge/authority.mjs";
import { fixture } from "./knowledge_fixture.mjs";

const DAY = 86400000;
const row = (id, provider, state, createdAt, units = 1) => ({ id, provider, units, background: false, job_id: null,
  state, created_at: createdAt, updated_at: createdAt });

test("a full ledger prunes rows outside the daily window before refusing work", async () => {
  const f = await fixture();
  const now = Date.parse("2026-09-25T00:00:00Z");
  const authority = new KnowledgeAuthority(f.storage, () => now);
  for (let i = 0; i < 6000; i++) await f.storage.put(`reservation:old-${i}`, row(`old-${i}`, "exa", i % 3 ? "confirmed" : "unknown", now - 2 * DAY));
  const reservation = await authority.call("reserve", { operation_id: "fresh", provider: "exa", background: false });
  assert.equal(reservation.replay, false);
  const status = await authority.call("snapshot");
  assert.deepEqual(status.ledger, { rows: 1, limit: 5000, counting: 1, pending: 1, unknown: 0 });
  assert.equal(status.usage.find(item => item.provider === "exa").total, 1);
});

test("a day of real traffic is still bounded and credit charges are never pruned unresolved", async () => {
  const f = await fixture();
  const now = Date.parse("2026-09-25T00:00:00Z");
  const authority = new KnowledgeAuthority(f.storage, () => now);
  await f.storage.put("reservation:credits", row("credits", "alexandria", "unknown", now - 40 * DAY, 15));
  for (let i = 0; i < 4999; i++) await f.storage.put(`reservation:recent-${i}`, row(`recent-${i}`, "exa", "confirmed", now - 1000, 0));
  await assert.rejects(authority.call("reserve", { operation_id: "overflow", provider: "exa", background: false }),
    { code: "ledger_full", status: 503 });
  await authority.call("maintenance");
  assert.ok(await f.storage.get("reservation:credits"), "an unresolved credit charge waits for its receipt");
  assert.equal((await authority.call("snapshot")).ledger.rows, 5000);
});
