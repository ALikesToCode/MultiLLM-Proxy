import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { scryptSync } from "node:crypto";
import { promisify } from "node:util";
import { account, database, usersCall } from "./support/config_revision_fixtures.mjs";

// Drives the registered Flask auth path, so it runs with the Python dependencies installed.
test("a key revoked by the real writer is rejected by registered Flask auth before memo expiry", async t => {
  const { env, revisions } = await database(t);
  const digest = scryptSync("synthetic-revision-key", "synthetic-salt", 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }).toString("hex");
  const user = account({ api_key_hash: `scrypt:32768:8:1$synthetic-salt$${digest}` });
  const states = [];
  for (const revoked_at of [null, "2026-10-09T01:00:00+00:00"]) {
    assert.equal((await usersCall(env, { operation: "upsert", user: { ...user, revoked_at } })).status, 200);
    states.push({ users: (await usersCall(env, { operation: "list", after: null, limit: 200 })).body.users,
      revisions: (await revisions(["key_controls", "model_grants"])).body.revisions });
  }
  // Pass only synthetic committed snapshots across the process boundary, never a
  // private HTTP endpoint or the host environment. The Python harness rejects IO.
  const script = `import os, sys, json, types
r = os.getcwd()
sys.path.insert(0, r)
sys.path.insert(0, os.path.join(r, "tests"))
sys.modules["env_loader"] = types.SimpleNamespace(load_runtime_env=lambda *a, **kw: None)
import test_knowledge_onboarding
from test_config_revision_sync import exercise_registered_writer_states
exercise_registered_writer_states(json.loads(sys.argv[1]))
print("registered-revocation-ok")`;
  const run = promisify(execFile);
  const python = process.env.PYTHON || "python3";
  const result = await run(python, ["-I", "-c", script, JSON.stringify(states)],
    { cwd: process.cwd(), env: { PATH: process.env.PATH }, timeout: 30000 });
  assert.match(result.stdout, /registered-revocation-ok/);
});
