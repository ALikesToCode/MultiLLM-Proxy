import assert from "node:assert/strict";
import test from "node:test";
import { fixture } from "./knowledge_fixture.mjs";

test("learning and rebuild finish on the first partial storage page", async () => {
  const f = await fixture();
  const artifact = await f.published();
  const list = f.storage.list.bind(f.storage);
  const calls = new Map();
  f.storage.list = async ({ prefix }) => {
    calls.set(prefix, (calls.get(prefix) ?? 0) + 1);
    assert.ok(calls.get(prefix) <= 1, "a partial page terminates that scan");
    return list({ prefix });
  };
  await f.authority.call("product_sites.learn", { id: artifact.id });
  calls.clear();
  const rebuilt = await f.authority.call("product_sites.update", { product: "flask", rebuild: true });
  assert.equal(rebuilt.sites["palletsprojects.com"].verified, 1);
});
