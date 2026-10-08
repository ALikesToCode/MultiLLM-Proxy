import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { handleIntelligenceOutbound } from "../worker/intelligence-outbound.mjs";
import { applyMigrations, migrationNames } from "./d1_migrations.mjs";

const template = { slug: "greeting", version: 1, content: "Hello {{name}} / {{name}}", variables: ["name"] };
const content_hash = createHash("sha256").update(template.content).digest("hex");
const record = { ...template, content_hash };
const now = Date.now() / 1000;
async function database(t, skip = []) {
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: "export default {fetch(){return new Response(\"ok\")}}", d1Databases: ["INTELLIGENCE_DB"] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database("INTELLIGENCE_DB");
  await applyMigrations(db, { skip });
  const call = async (body, overrides = {}) => {
    const response = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/state/prompt-templates", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ version: 1, principal: "owner", ...body }),
    }), { INTELLIGENCE_DB: db, PROMPT_TEMPLATES_ENABLED: "true", ...overrides });
    return { status: response.status, body: await response.json() };
  };
  return { db, call };
}
const create = (change = {}) => ({ operation: "create", template: record, created_at: now, ...change });

test("private prompt domain is default off without storage, parsing or side effects", async () => {
  for (const setting of [undefined, "false", "invalid"]) {
    const response = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/state/prompt-templates", {
      method: "POST", headers: { "content-type": "application/json" }, body: "invalid",
    }), { PROMPT_TEMPLATES_ENABLED: setting, INTELLIGENCE_DB: { prepare() { throw new Error("storage touched"); } } });
    assert.equal(response.status, 404);
  }
});

test("D1 versions are immutable, scoped and atomic under concurrency", async t => {
  const { db, call } = await database(t);
  const outcomes = await Promise.all(Array.from({ length: 4 }, () => call(create())));
  assert.deepEqual(outcomes.map(row => row.status).sort(), [200, 409, 409, 409]);
  assert.equal((await call(create({ principal: "other" }))).status, 200);
  assert.equal((await call(create({ template: { ...record, version: 2 } }))).status, 200);
  assert.deepEqual((await call({ operation: "get", slug: "greeting", template_version: 1 })).body.template, record);
  assert.deepEqual((await call({ operation: "get", principal: "absent", slug: "greeting", template_version: 1 })).body.template, null);
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM prompt_templates").first()).n, 3);
  assert.equal((await call({ operation: "update", template: record })).status, 400);
  assert.equal((await call({ operation: "delete", slug: "greeting", template_version: 1 })).status, 400);
});

test("D1 validates declarations, hashes, bytes and exact fixed fields before SQL", async t => {
  const { call } = await database(t);
  for (const change of [{ variables: ["name", "name"] }, { variables: ["extra"] }, { version: true }, { slug: "../x" },
    { content_hash: "a".repeat(64) }, { content: "{{name.upper()}}" }, { content: "{{ name }}" }, { content: "{% include x %}" },
    { content: "😀".repeat(16385) }, { principal: "other" }]) {
    assert.equal((await call(create({ template: { ...record, ...change } }))).status, 400);
  }
  for (const change of [{ principal: "" }, { principal: [] }, { extra: true }, { created_at: "now" }, { created_at: now + 3600 }]) {
    assert.equal((await call(create(change))).status, 400);
  }
  assert.equal((await call({ operation: "get", slug: "greeting", template_version: true })).status, 400);
  const response = await handleIntelligenceOutbound(new Request("http://intelligence.internal/v1/state/prompt-templates", {
    method: "POST", headers: { "content-type": "application/json" }, body: "x".repeat(524289),
  }), { INTELLIGENCE_DB: { prepare() { throw new Error("SQL must not run"); } }, PROMPT_TEMPLATES_ENABLED: "true" });
  assert.equal(response.status, 400);
});

test("D1 logical retention and pagination preserve version uniqueness", async t => {
  const { call } = await database(t);
  for (let version = 1; version <= 4; version++) assert.equal((await call(create({ template: { ...record, version } }))).status, 200);
  const page = (await call({ operation: "list", after: null })).body;
  assert.deepEqual(page.templates, [record, { ...record, version: 2 }]);
  assert.deepEqual(page.next, { slug: "greeting", version: 2 });
  assert.deepEqual((await call({ operation: "list", after: page.next })).body.templates.map(row => row.version), [3, 4]);
  assert.equal((await call(create({ principal: "expired", created_at: now - 30 * 86400 - 1 }))).status, 200);
  assert.equal((await call({ operation: "get", principal: "expired", slug: "greeting", template_version: 1 })).body.template, null);
  assert.equal((await call(create({ principal: "expired" }))).status, 409);
});

test("enabled missing migration fails closed with 503 and keeps old rows", async t => {
  const { db, call } = await database(t, ["0014_prompt_templates.sql"]);
  await db.prepare("INSERT INTO control_connection_profiles (id, owner, name, settings, created_at) VALUES (?, ?, ?, ?, ?)").bind("old", "owner", "old", "{}", 1).run();
  for (const body of [create(), { operation: "list", after: null }, { operation: "get", slug: "greeting", template_version: 1 }]) {
    const response = await call(body);
    assert.equal(response.status, 503);
    assert.equal(response.body.error.code, "storage_unavailable");
  }
  const skip = (await migrationNames()).filter(name => name !== "0014_prompt_templates.sql");
  await applyMigrations(db, { skip });
  await applyMigrations(db, { skip });
  assert.equal((await db.prepare("SELECT name FROM control_connection_profiles WHERE id = ?").bind("old").first()).name, "old");
  assert.equal((await call(create())).status, 200);
});


test("D1 and SQLite return the same versions, conflicts, page and literal rendering", async t => {
  const { call } = await database(t);
  assert.equal((await call(create())).status, 200);
  const python = spawnSync("/home/mysterious/storage/github/MultiLLM-Proxy/.venv/bin/python", ["-I", "-c", `
import json, os, sys, tempfile, types
sys.path.insert(0, os.getcwd())
sys.modules["env_loader"] = types.SimpleNamespace(load_runtime_env=lambda *args, **kwargs: None)
from services.prompt_templates import PromptTemplateStore, render_template
from error_handlers import APIError
with tempfile.TemporaryDirectory(prefix="prompt-parity-") as scratch:
    os.environ["CONNECTION_PROFILES_DB_PATH"] = scratch + "/workbench.sqlite3"
    os.environ["CONTROL_PLANE_DATABASE_URL"] = ""
    os.environ["INTELLIGENCE_STORAGE_BACKEND"] = ""
    value = ${JSON.stringify(template)}
    saved = PromptTemplateStore.create("owner", value)
    try:
        PromptTemplateStore.create("owner", value)
    except APIError as error:
        conflict = error.status_code
    print(json.dumps({"template": PromptTemplateStore.get("owner", "greeting", 1),
        "page": PromptTemplateStore.list("owner"), "other": PromptTemplateStore.list("other"),
        "conflict": conflict, "render": render_template(saved, {"name": r"{{next}} \\1"})}))
`], { cwd: fileURLToPath(new URL("../", import.meta.url)), encoding: "utf8", timeout: 15000,
    env: { PATH: process.env.PATH } });
  assert.equal(python.status, 0, python.stderr);
  const sqlite = JSON.parse(python.stdout);
  assert.deepEqual((await call({ operation: "get", slug: "greeting", template_version: 1 })).body.template, sqlite.template);
  const page = (await call({ operation: "list", after: null })).body;
  assert.deepEqual({ templates: page.templates, next: page.next }, sqlite.page);
  const other = (await call({ operation: "list", principal: "other", after: null })).body;
  assert.deepEqual({ templates: other.templates, next: other.next }, sqlite.other);
  assert.equal((await call(create())).status, sqlite.conflict);
  assert.equal(sqlite.render.rendered, "Hello {{next}} \\1 / {{next}} \\1");
  assert.equal(sqlite.render.content_hash, content_hash);
});

test("D1 owner bounds and driver failures never expose bound content", async t => {
  const { call } = await database(t);
  const outcomes = await Promise.all(Array.from({ length: 102 }, (_, index) => call(create({ template: { ...record, version: index + 1 } }))));
  assert.equal(outcomes.filter(row => row.status === 200).length, 100);
  assert.equal(outcomes.filter(row => row.status === 409).length, 2);
  const response = await call(create(), { INTELLIGENCE_DB: { prepare() { throw new Error("sensitive template content"); } } });
  assert.equal(response.status, 503);
  assert.equal(JSON.stringify(response.body).includes("sensitive"), false);
});
