import assert from "node:assert/strict";
import test from "node:test";
import { accountPolicyVersion, accountReply, accountWrite } from "../worker/account-contract.mjs";

test("account policy negotiation is explicit and rejects unknown versions", () => {
  assert.equal(accountPolicyVersion({ version: 1 }), null);
  const body = { version: 1, data_policy_version: 1 };
  assert.equal(accountPolicyVersion(body), 1);
  assert.deepEqual(body, { version: 1 });
  for (const value of [null, false, "1", 0, 2]) assert.throws(() => accountPolicyVersion({ data_policy_version: value }));
});
test("legacy account projection refuses missing or malformed verification", () => {
  for (const data_policy of [undefined, null, {}, { version: 1, official_only: null }]) {
    assert.throws(() => accountReply({ username: "synthetic", official_only: null,
      forced_provider_preferences: null, data_policy }, null));
  }
  assert.throws(() => accountWrite({ username: "synthetic", official_only: 0 }, null));
  assert.deepEqual(accountWrite({ username: "synthetic" }, null), {
    username: "synthetic", official_only: null, forced_provider_preferences: null,
  });
});


test("zero and empty policies survive the negotiated account reply", () => {
  for (const policy of [{ official_only: 0, forced_provider_preferences: null },
    { official_only: null, forced_provider_preferences: {} }]) {
    const row = { username: "synthetic", ...policy, data_policy: { version: 1, ...policy } };
    assert.equal(accountReply(row, 1), row);
    assert.deepEqual(accountReply(row, null), { username: "synthetic" });
  }
});
