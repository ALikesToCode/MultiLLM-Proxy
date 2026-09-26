/**
 * Python account, auto-route and control-state code -> the Worker's private handlers -> a real local D1,
 * with and without the migrations applied. Runs in CI where both Python and Node exist.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import test from "node:test";
import { promisify } from "node:util";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";

import { applyMigrations } from "./d1_migrations.mjs";

const run = promisify(execFile);
const PYTHON = process.env.PYTHON || (existsSync(".venv/bin/python") ? ".venv/bin/python" : "python3");
const bundled = await build({ stdin: { resolveDir: process.cwd(), sourcefile: "private-store.mjs", contents: `
  import { handleIntelligenceOutbound } from './worker/intelligence-outbound.mjs';
  export default { fetch(request, env) {
    const url = new URL(request.url);
    return handleIntelligenceOutbound(new Request('http://intelligence.internal' + url.pathname, request), env);
  } };
` }, bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:*", "node:*"], write: false });

async function privateStore(t, skip = []) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundled.outputFiles[0].text,
    compatibilityDate: "2026-07-30", host: "127.0.0.1", port: 0, d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db, { skip });
  return { db, url: (await mf.ready).href };
}

async function driveState(url, scenario) {
  const { stdout } = await run(PYTHON, ["-I", "tests/support/d1_control_state_driver.py", scenario],
    { env: { PATH: process.env.PATH, PRIVATE_BASE_URL: url }, timeout: 120000 });
  return JSON.parse(stdout.trim().split("\n").at(-1));
}

async function drive(url, scenario) {
  const { stdout } = await run(PYTHON, ["-I", "tests/support/d1_accounts_driver.py", scenario],
    { env: { PATH: process.env.PATH, PRIVATE_BASE_URL: url }, timeout: 120000 });
  return JSON.parse(stdout.trim().split("\n").at(-1));
}

test("accounts, the admin allowlist, audit rows and auto routes persist through the Worker in D1", async t => {
  const { db, url } = await privateStore(t);
  assert.deepEqual(await drive(url, "migrated"), { agent: "agent", wrong_key: null, admin: true, admin_refused: 403,
    route: ["gguu:gpt-image-2.5", "openai:gpt-image-2.5"], users: 2 });
  const users = (await db.prepare("SELECT username, is_admin FROM control_users ORDER BY username").all()).results;
  assert.deepEqual(users, [{ username: "admin", is_admin: 1 }, { username: "agent", is_admin: 0 }]);
  const audit = (await db.prepare("SELECT outcome, username FROM control_user_audit ORDER BY id").all()).results;
  assert.ok(audit.some(row => row.outcome === "refused" && row.username === "mallory"));
  assert.ok(audit.some(row => row.outcome === "stored" && row.username === "agent"));
});

test("a D1 without the account migration fails closed for dashboard keys but not for the environment admin", async t => {
  const { url } = await privateStore(t, ["0003_control_users.sql", "0004_control_user_audit.sql", "0005_auto_routes.sql"]);
  assert.deepEqual(await drive(url, "unmigrated"), { dashboard_key: 503, admin: "admin",
    route: ["gguu:gpt-image-2.5-sunburst", "gguu:gpt-image-2.5"], save_route: 503 });
});

test("control-plane state survives Container restarts through the Worker in D1", async t => {
  const { db, url } = await privateStore(t);
  assert.deepEqual(await driveState(url, "migrated"), {
    usage: ["allowed", "allowed", "daily_budget_exceeded", "allowed", "daily_budget_exceeded"],
    login: [true, false, false], status: "disabled", cooldown: true, profiles: ["Flash"], catalog: 401, catalog_limit: 200000,
    local_files: [] });
  const identities = (await db.prepare("SELECT DISTINCT identity FROM control_rate_usage").all()).results;
  assert.equal(identities.length, 1);
  assert.match(identities[0].identity, /^[0-9a-f]{64}$/, "usage rows hold a keyed hash, not the username");
});

test("before migration 0006 requests and sign-in keep working and admin saves fail visibly", async t => {
  const { url } = await privateStore(t, ["0006_control_state.sql"]);
  assert.deepEqual(await driveState(url, "unmigrated"), { usage: ["allowed", "allowed", "daily_budget_exceeded"],
    login: [true, false], status: "available", disable: 503, profile: 503, cooldown: true, catalog: false, catalog_models: 1 });
});
