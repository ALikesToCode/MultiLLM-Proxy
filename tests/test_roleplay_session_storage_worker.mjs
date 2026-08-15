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
  }

  async get(key) {
    return structuredClone(this.values.get(key));
  }

  async put(entries) {
    for (const [key, value] of Object.entries(entries)) {
      assert.ok(
        encodedBytes(value) <= MAX_TEST_VALUE_BYTES,
        `${key} exceeded the simulated durable value limit`,
      );
      this.values.set(key, structuredClone(value));
    }
  }
}

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
