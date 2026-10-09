import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { handleSamlIdentityRequest } from "../worker/saml-identity.mjs";
import { loadWorkerModule } from "./helpers/load_cloudflare_worker.mjs";

const hash = character => character.repeat(64);
const now = Math.floor(Date.now() / 1000);
const request = (body, url = "http://intelligence.internal/v1/managed-state/saml", headers = {}) => new Request(url, {
  method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ version: 1, ...body }) });

function database(sql) {
  return { prepare(query) {
    let values = [];
    return { bind(...args) { values = args; return this; }, first() { return sql.prepare(query).get(...values) ?? null; },
      all() { const stmt = sql.prepare(query); return stmt.columns().length ? { results: stmt.all(...values), meta: { changes: 0 } }
        : { results: [], meta: { changes: Number(stmt.run(...values).changes) } }; }, run() { return this.all(); } };
  }, async batch(statements) {
    sql.exec("BEGIN IMMEDIATE");
    try { const result = statements.map(statement => statement.all()); sql.exec("COMMIT"); return result; }
    catch (error) { sql.exec("ROLLBACK"); throw error; }
  } };
}

async function fixture(t) {
  const sql = new DatabaseSync(":memory:"); t.after(() => sql.close());
  sql.exec(await readFile(new URL("../intelligence-migrations/0003_control_users.sql", import.meta.url), "utf8"));
  sql.prepare("INSERT INTO control_users(username,api_key_hash,api_key_prefix,scopes,created_at) VALUES(?,?,?,?,?)").run("alice", "synthetic", "synthetic", "chat", "2026-01-01");
  const migration = await readFile(new URL("../intelligence-migrations/0035_saml_federation.sql", import.meta.url), "utf8");
  sql.exec(migration); sql.exec(migration);
  const env = { SAML_ENABLED: "true", INTELLIGENCE_DB: database(sql) };
  return { sql, env, call: (body, settings = env) => handleSamlIdentityRequest(request(body), settings) };
}

test("default-off private handler reads no body or storage", async () => {
  for (const flag of [undefined, "", "false", "0"]) {
    const response = await handleSamlIdentityRequest(request({ operation: "ready" }), { SAML_ENABLED: flag,
      INTELLIGENCE_DB: { prepare() { assert.fail("disabled storage"); } } });
    assert.equal(response.status, 404);
  }
});

test("nonce digests expire and concurrent claim is exactly once", async t => {
  const { sql, call } = await fixture(t);
  const body = { state_digest: hash("a"), nonce_digest: hash("b"), recipient_digest: hash("c"), now, expires_at: now + 300 };
  assert.equal((await call({ operation: "create_request", ...body })).status, 200);
  const claim = { operation: "claim_request", state_digest: body.state_digest, nonce_digest: body.nonce_digest, recipient_digest: body.recipient_digest, now };
  assert.equal((await (await call({ ...claim, nonce_digest: hash("d") })).json()).claimed, false);
  const responses = await Promise.all([call(claim), call(claim)]);
  const claimed = await Promise.all(responses.map(async response => (await response.json()).claimed));
  assert.deepEqual(claimed.sort(), [false, true]);
  assert.equal(sql.prepare("SELECT claimed_at FROM saml_requests").get().claimed_at, now);
  assert.equal((await (await call(claim)).json()).claimed, false);
  assert.equal((await call({ operation: "create_request", ...body, state_digest: hash("e"), expires_at: now + 301 })).status, 400);
  await call({ operation: "create_request", ...body, state_digest: hash("f"), expires_at: now + 1 });
  assert.equal((await (await call({ ...claim, state_digest: hash("f"), now: now + 1 })).json()).claimed, false);
});

test("links refer to existing accounts, remain scoped and retain audit and tombstones", async t => {
  const { sql, call } = await fixture(t);
  const link = { id: "a".repeat(32), issuer_digest: hash("a"), subject_digest: hash("b"), account: "alice", org_id: "org:one", team_id: "team:one", grants_revision: 2 };
  const put = { operation: "put_link", link, actor: "operator", now };
  assert.equal((await call({ ...put, link: { ...link, account: "missing" } })).status, 403);
  assert.equal((await call(put)).status, 200);
  assert.equal((await (await call({ operation: "lookup_link", issuer_digest: hash("c"), subject_digest: hash("b") })).json()).link, null);
  assert.equal((await (await call({ operation: "lookup_link", issuer_digest: hash("a"), subject_digest: hash("b") })).json()).link.team_id, "team:one");
  assert.equal((await call({ operation: "deactivate_link", id: link.id, actor: "operator", now })).status, 200);
  assert.equal(sql.prepare("SELECT active FROM saml_subject_links").get().active, 0);
  assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM saml_audit").get().n, 2);
  assert.match(sql.prepare("SELECT actor_digest FROM saml_audit LIMIT 1").get().actor_digest, /^[a-f0-9]{64}$/);
  assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM control_users").get().n, 1);
  assert.equal((await (await call({ operation: "list_links", offset: 0 })).json()).links.length, 1);
});

test("missing any table fails before writes and hides storage details", async t => {
  const { call } = await fixture(t);
  const sql = new DatabaseSync(":memory:"); t.after(() => sql.close());
  const response = await call({ operation: "ready" }, { SAML_ENABLED: "true", INTELLIGENCE_DB: database(sql) });
  assert.equal(response.status, 503); assert.equal((await response.json()).error.code, "saml_storage_unavailable");
});

for (const table of ["saml_requests", "saml_subject_links", "saml_audit"]) test("missing " + table + " refuses request creation before mutations", async t => {
  const { sql, call } = await fixture(t);
  sql.exec(`DROP TABLE ${table}`);
  const response = await call({ operation: "create_request", state_digest: hash("a"), nonce_digest: hash("b"), recipient_digest: hash("c"), now, expires_at: now + 300 });
  assert.equal(response.status, 503); assert.equal((await response.json()).error.code, "saml_storage_unavailable");
  if (table !== "saml_requests") assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM saml_requests").get().n, 0);
});

test("missing audit column fails before request creation", async t => {
  const { sql, call } = await fixture(t);
  sql.exec("ALTER TABLE saml_audit DROP COLUMN actor_digest");
  const response = await call({ operation: "create_request", state_digest: hash("a"), nonce_digest: hash("b"), recipient_digest: hash("c"), now, expires_at: now + 300 });
  assert.equal(response.status, 503); assert.equal((await response.json()).error.code, "saml_storage_unavailable");
  assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM saml_requests").get().n, 0);
});

test("audit transaction failure rolls back a subject link and existing accounts survive migration", async t => {
  const { sql, call } = await fixture(t);
  sql.exec("CREATE TRIGGER refuse_audit BEFORE INSERT ON saml_audit BEGIN SELECT RAISE(ABORT, 'synthetic audit outage'); END");
  const link = { id: "a".repeat(32), issuer_digest: hash("a"), subject_digest: hash("b"), account: "alice", org_id: null, team_id: null, grants_revision: 0 };
  assert.equal((await call({ operation: "put_link", link, actor: "operator", now })).status, 503);
  assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM saml_subject_links").get().n, 0);
  assert.equal(sql.prepare("SELECT username,scopes,is_admin FROM control_users").get().username, "alice");
  assert.equal(sql.prepare("SELECT scopes,is_admin FROM control_users").get().scopes, "chat");
  assert.equal(sql.prepare("SELECT is_admin FROM control_users").get().is_admin, 0);
});

test("changing a link binding cannot move its history or grant administrator attributes", async t => {
  const { sql, call } = await fixture(t);
  const link = { id: "a".repeat(32), issuer_digest: hash("a"), subject_digest: hash("b"), account: "alice", org_id: "org:one", team_id: null, grants_revision: 0 };
  assert.equal((await call({ operation: "put_link", link, actor: "operator", now })).status, 200);
  assert.equal((await call({ operation: "put_link", link: { ...link, subject_digest: hash("c") }, actor: "operator", now })).status, 409);
  assert.equal((await call({ operation: "put_link", link: { ...link, is_admin: true }, actor: "operator", now })).status, 400);
  assert.equal((await call({ operation: "put_link", link: { ...link, org_id: null, team_id: "team:foreign" }, actor: "operator", now })).status, 400);
  assert.equal(sql.prepare("SELECT subject_digest FROM saml_subject_links").get().subject_digest, hash("b"));
  assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM saml_audit").get().n, 1);
});

test("private target and strict bounded envelopes reject arbitrary operations", async t => {
  const { call, env } = await fixture(t);
  for (const url of ["https://intelligence.internal/v1/managed-state/saml", "http://other.internal/v1/managed-state/saml", "http://intelligence.internal/v1/managed-state/saml?sql=1"])
    assert.equal((await handleSamlIdentityRequest(request({ operation: "ready" }, url), env)).status, 404);
  for (const body of [{ operation: "sql", statement: "DROP TABLE control_users" }, { operation: "ready", extra: true },
    { operation: "audit", issuer_digest: hash("a"), account: null, outcome: "raw assertion", now }, { operation: "list_links", offset: -1 }])
    assert.equal((await call(body)).status, 400);
  const oversized = request({ operation: "ready", pad: "x".repeat(9000) });
  assert.equal((await handleSamlIdentityRequest(oversized, env)).status, 400);
});

test("the existing Worker forwards SAML URL, method, cookies and token body to the Container", async () => {
  const { default: worker } = await loadWorkerModule();
  for (const [path, method, body] of [["/auth/saml/login?next=fixture", "GET", undefined], ["/auth/saml/callback?state=fixture", "POST", "token=synthetic&state=fixture"], ["/auth/saml/metadata", "GET", undefined]]) {
    let forwarded;
    const response = await worker.fetch(new Request("https://gateway.example" + path, { method, body, headers: { cookie: "session=synthetic", "content-type": "application/x-www-form-urlencoded" } }), {
      MULTILLM_PROXY_CONTAINER: { getByName: () => ({ async fetch(req) { forwarded = req; return new Response("container-result", { status: 503 }); } }) }
    }, {});
    assert.equal(response.status, 503); assert.equal(await response.text(), "container-result");
    assert.equal(forwarded.url, "https://gateway.example" + path); assert.equal(forwarded.method, method);
    assert.equal(forwarded.headers.get("cookie"), "session=synthetic"); assert.equal(await forwarded.text(), body ?? "");
  }
});
