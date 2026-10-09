import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as ec from "../worker/enterprise-contract.mjs";

const vectors = JSON.parse(readFileSync(new URL("../docs/enterprise-contracts.md", import.meta.url), "utf8")
  .split("```json\n")[1].split("```")[0]);
for (const vector of vectors) {
  test(`shared contract vector: ${vector.name}`, () => {
    const data = { ...vector.data };
    if (data.context) data.context = new ec.TenantContext(data.context);
    if (!vector.valid) return assert.throws(() => new ec[vector.type](data));
    const value = new ec[vector.type](data);
    assert.ok(Object.isFrozen(value));
    assert.throws(() => { value.principal_id = "changed"; }, TypeError);
  });
}

function operation(changes = {}) {
  const data = vectors.find(vector => vector.name === "operation").data;
  return new ec.AuthorityOperation({ ...data, context: new ec.TenantContext(data.context), ...changes });
}
function result(op, changes = {}) {
  return new ec.AuthorityResult({ context: op.context, scoped_id: op.scoped_id, revision: 8,
    operation_id: op.operation_id, allowed: true, ...changes });
}

test("legacy single principal and missing authorities deny tenant and money grants", async () => {
  const op = operation();
  const adapters = ec.registerEnterpriseAdapters();
  assert.deepEqual(await ec.resolveTenant(adapters, op), op.context);
  await assert.rejects(ec.resolveTenant(adapters, operation({ context: new ec.TenantContext({ principal_id: "principal:one", org_id: "org:one" }) })), /tenant_scope_denied/);
  for (const authority of ["quota", "credit"]) for (const action of ["reserve", "commit", "reconcile"]) {
    await assert.rejects(ec.callAuthority(adapters, authority, action, op), /authority_unavailable/);
  }
});

test("fake quota and credit enforce operation and atomic revision boundaries", async () => {
  const op = operation();
  const calls = [];
  const call = async value => { calls.push(value); return result(value); };
  const fake = Object.freeze({ reserve: call, commit: call, reconcile: call });
  const adapters = ec.registerEnterpriseAdapters({ quota: fake, credit: fake, tenant: value => value.context });
  for (const authority of ["quota", "credit"]) for (const action of ["reserve", "commit", "reconcile"]) {
    assert.equal((await ec.callAuthority(adapters, authority, action, op)).revision, 8);
  }
  assert.deepEqual(calls, Array(6).fill(op));
  for (const change of [{ revision: 7 }, { operation_id: "other" }, { scoped_id: "other" },
    { context: new ec.TenantContext({ principal_id: "foreign" }) }, { allowed: false }]) {
    const denied = () => result(op, change);
    await assert.rejects(ec.callAuthority(ec.registerEnterpriseAdapters({ credit: { reserve: denied, commit: denied, reconcile: denied } }), "credit", "reserve", op), ec.AuthorityDenied);
  }
});

test("identity and payment accept only verified immutable scoped inputs", async () => {
  const op = operation();
  const assertion = new ec.IdentityAssertion({ issuer_id: "issuer:one", subject_id: "subject:one", audience_id: "audience:one",
    request_id: "request:one", nonce_id: "nonce:one", expires_at: 1000, verified: true });
  const event = new ec.PaymentEvent({ context: op.context, scoped_id: op.scoped_id, revision: 7,
    idempotency_id: op.operation_id, processor_id: "processor:one", event_id: "event:one", kind: "credit",
    currency: "USD", amount: 12, verified: true });
  const empty = ec.registerEnterpriseAdapters();
  await assert.rejects(ec.resolveIdentity(empty, assertion, op), ec.AuthorityDenied);
  await assert.rejects(ec.deliverPayment(empty, event), ec.AuthorityDenied);
  const calls = [];
  const adapters = ec.registerEnterpriseAdapters({ identity: (value, request) => { assert.equal(value, assertion); return request.context; },
    payment: value => { calls.push(value); return result(op); } });
  assert.deepEqual(await ec.resolveIdentity(adapters, assertion, op), op.context);
  assert.equal((await ec.deliverPayment(adapters, event)).revision, 8);
  assert.deepEqual(calls, [event]);
  await assert.rejects(ec.deliverPayment(adapters, { verified: true }), TypeError);
  await assert.rejects(ec.resolveIdentity(ec.registerEnterpriseAdapters({ identity: () => new ec.TenantContext({ principal_id: "foreign" }) }), assertion, op), ec.AuthorityDenied);
});

test("preview settings and descriptor have no authority side effects", () => {
  for (const value of [undefined, "", "false", "0", "off", "no"]) {
    assert.equal(ec.previewEnabled({ ENTERPRISE_PREVIEW_ENABLED: value }), false);
  }
  for (const value of ["true", "1", "YES", " on "]) assert.equal(ec.previewEnabled({ ENTERPRISE_PREVIEW_ENABLED: value }), true);
  const warnings = [];
  for (let i = 0; i < 2; i++) assert.equal(ec.previewEnabled({ ENTERPRISE_PREVIEW_ENABLED: "private-invalid" }, message => warnings.push(message)), false);
  assert.equal(warnings.length, 1);
  assert.doesNotMatch(warnings[0], /private-invalid/);
  const fail = () => { throw new Error("Descriptor called authority"); };
  const adapters = ec.registerEnterpriseAdapters({ tenant: fail, payment: fail });
  assert.equal(ec.previewDescriptor(adapters).dry_run, true);
  assert.ok(Object.isFrozen(adapters));
});

test("fake credit atomic revision and idempotency", async () => {
  const op = operation();
  let revision = op.revision;
  const records = new Map(), writes = [];
  const apply = value => {
    if (records.has(value.operation_id)) {
      const record = records.get(value.operation_id);
      if (JSON.stringify(record.operation) !== JSON.stringify(value)) throw new ec.AuthorityDenied("operation_conflict");
      return record.result;
    }
    if (value.revision !== revision) throw new ec.AuthorityDenied("revision_conflict");
    const decision = result(value, { revision: ++revision });
    records.set(value.operation_id, { operation: value, result: decision });
    writes.push(value);
    return decision;
  };
  const adapters = ec.registerEnterpriseAdapters({ tenant: null, credit: { reserve: apply, commit: apply, reconcile: apply } });
  await assert.rejects(ec.resolveTenant(adapters, op), ec.AuthorityDenied);
  const results = await Promise.all([ec.callAuthority(adapters, "credit", "reserve", op), ec.callAuthority(adapters, "credit", "reserve", op)]);
  assert.deepEqual(results[0], results[1]);
  assert.deepEqual(writes, [op]);
  await assert.rejects(ec.callAuthority(adapters, "credit", "reserve", operation({ amount: 13 })), /operation_conflict/);
  await assert.rejects(ec.callAuthority(adapters, "credit", "commit", operation({ operation_id: "operation:two" })), /revision_conflict/);
  const next = operation({ revision: 8, operation_id: "operation:two" });
  assert.equal((await ec.callAuthority(adapters, "credit", "commit", next)).revision, 9);
  assert.deepEqual(writes, [op, next]);
});

test("adapter failure is not retried or converted to success", async () => {
  let calls = 0;
  const fail = () => { calls++; throw new Error("authority unavailable"); };
  await assert.rejects(ec.callAuthority(ec.registerEnterpriseAdapters({ credit: { reserve: fail, commit: fail, reconcile: fail } }), "credit", "reserve", operation()), /authority unavailable/);
  assert.equal(calls, 1);
  assert.throws(() => ec.registerEnterpriseAdapters({ tenant: "plugin.module" }), TypeError);
});
