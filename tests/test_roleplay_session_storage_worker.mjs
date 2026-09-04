import assert from "node:assert/strict";
import test from "node:test";

import {
  createInitialRoleplayState,
  loadRoleplayState,
  saveRoleplayState,
} from "../worker/roleplay/session-storage.mjs";

const MAX_TEST_VALUE_BYTES = 1_500_000;

function encodedBytes(value) {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

class SizeBoundStorage {
  constructor() {
    this.values = new Map();
    this.writes = [];
  }

  async get(key) {
    return structuredClone(this.values.get(key));
  }

  async put(entries) {
    this.writes.push(Object.keys(entries).sort());
    for (const [key, value] of Object.entries(entries)) {
      assert.ok(
        encodedBytes(value) <= MAX_TEST_VALUE_BYTES,
        `${key} exceeded the simulated durable value limit`,
      );
      this.values.set(key, structuredClone(value));
    }
  }
}

test("unchanged message partitions are not rewritten with core state", async () => {
  const storage = new SizeBoundStorage();
  const initial = {
    ...createInitialRoleplayState(),
    messages: [{ role: "user", content: "Remember this." }],
    directives: [{ role: "system", content: "Stay in character." }],
  };
  await saveRoleplayState(storage, initial);
  storage.writes = [];

  const updated = { ...initial, turns: 1 };
  await saveRoleplayState(storage, updated, initial);

  assert.deepEqual(storage.writes, [["roleplay-session"]]);
});

test("long protected directives are sharded and reconstructed losslessly", async () => {
  const storage = new SizeBoundStorage();
  const content = `${"a".repeat(1_599_999)}😀tail`;
  const state = {
    ...createInitialRoleplayState(),
    directives: [{ role: "system", content }],
  };

  await saveRoleplayState(storage, state);

  const manifest = await storage.get("roleplay-directives");
  assert.equal(manifest.format, "message-shards-v1");
  assert.ok(manifest.shards > 1);

  const loaded = await loadRoleplayState(storage);
  assert.equal(
    loaded.directives.map((directive) => directive.content).join(""),
    content,
  );
  for (const directive of loaded.directives) {
    assert.equal(/[\uD800-\uDBFF]$/.test(directive.content), false);
    assert.equal(/^[\uDC00-\uDFFF]/.test(directive.content), false);
  }
});

test("an explicit empty directive array overrides legacy core directives", async () => {
  const storage = new SizeBoundStorage();
  storage.values.set("roleplay-session", {
    directives: [{ role: "system", content: "legacy" }],
  });
  storage.values.set("roleplay-messages", []);
  storage.values.set("roleplay-directives", []);

  const loaded = await loadRoleplayState(storage);

  assert.deepEqual(loaded.directives, []);
});

test("legacy empty session messages are removed while valid history is preserved", async () => {
  const storage = new SizeBoundStorage();
  storage.values.set("roleplay-session", {});
  storage.values.set("roleplay-messages", [
    { role: "assistant", content: "" },
    { role: "user", content: "   " },
    { role: "user", content: "Keep this history." },
  ]);
  storage.values.set("roleplay-directives", [
    { role: "system", content: "\n\t" },
    { role: "system", content: "Keep this directive." },
    { role: "user", content: "Not a directive." },
  ]);

  const loaded = await loadRoleplayState(storage);

  assert.deepEqual(loaded.messages, [
    { role: "user", content: "Keep this history." },
  ]);
  assert.deepEqual(loaded.directives, [
    { role: "system", content: "Keep this directive." },
  ]);
});
