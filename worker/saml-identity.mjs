/** Private durable broker request claims, explicit subject links and content-free audit. */
const PATH = "/v1/managed-state/saml";
const MAX_BYTES = 8192;
const HASH = /^[a-f0-9]{64}$/;
const ID = /^[a-f0-9]{32}$/;
const OPAQUE = /^[A-Za-z0-9_:.\-]{1,128}$/;
const OUTCOMES = new Set(["authorized", "link_put", "link_deactivated", "saml_assertion_invalid", "saml_assertion_replayed",
  "saml_subject_unlinked", "saml_identity_denied", "saml_identity_unavailable", "saml_session_unavailable"]);
const LINK_COLUMNS = "id,issuer_digest,subject_digest,account,org_id,team_id,grants_revision,active,created_at,updated_at";
const fields = (body, names) => Object.keys(body).length === names.length + 2
  && ["version", "operation", ...names].every(name => Object.hasOwn(body, name));
const text = value => typeof value === "string" && value.length > 0 && value.length <= 128 && !/[\x00-\x1f\x7f]/.test(value);
const hash = value => typeof value === "string" && HASH.test(value);
const id = value => typeof value === "string" && ID.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0 && value < Number.MAX_SAFE_INTEGER;
const scope = value => value === null || (typeof value === "string" && OPAQUE.test(value));
const actorDigest = async value => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))))
  .map(byte => byte.toString(16).padStart(2, "0")).join("");
const reply = (value, status = 200) => Response.json(value.error
  ? { version: 1, error: { code: value.error, message: "SAML identity storage request could not be completed.", retryable: false } }
  : { version: 1, ...value }, { status, headers: { "cache-control": "no-store" } });
let warned = false;

function enabled(env) {
  const flag = typeof (env.SAML_ENABLED ?? "") === "string" ? (env.SAML_ENABLED ?? "").trim().toLowerCase() : "invalid";
  if (["", "false", "0", "off", "no"].includes(flag)) return false;
  if (["true", "1", "on", "yes"].includes(flag)) return true;
  if (!warned) { console.warn("Invalid SAML_ENABLED; federation disabled"); warned = true; }
  return false;
}

async function bodyDocument(request) {
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json" || !request.body)
    throw new Error("Invalid content type");
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BYTES)) throw new Error("Invalid length");
  const reader = request.body.getReader(), chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) { void reader.cancel().catch(() => {}); throw new Error("Oversized request"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!body || typeof body !== "object" || Array.isArray(body) || body.version !== 1) throw new Error("Invalid envelope");
  return body;
}

function validLink(link) {
  return link && typeof link === "object" && !Array.isArray(link)
    && Object.keys(link).length === 7 && ["id", "issuer_digest", "subject_digest", "account", "org_id", "team_id", "grants_revision"].every(key => Object.hasOwn(link, key))
    && id(link.id) && hash(link.issuer_digest) && hash(link.subject_digest) && text(link.account)
    && scope(link.org_id) && scope(link.team_id) && (link.team_id === null || link.org_id !== null) && integer(link.grants_revision);
}

function validOperation(body) {
  switch (body.operation) {
    case "ready": return fields(body, []);
    case "create_request": return fields(body, ["state_digest", "nonce_digest", "recipient_digest", "now", "expires_at"])
      && hash(body.state_digest) && hash(body.nonce_digest) && hash(body.recipient_digest) && integer(body.now) && integer(body.expires_at)
      && body.expires_at > body.now && body.expires_at <= body.now + 300;
    case "claim_request": return fields(body, ["state_digest", "nonce_digest", "recipient_digest", "now"])
      && hash(body.state_digest) && hash(body.nonce_digest) && hash(body.recipient_digest) && integer(body.now);
    case "lookup_link": return fields(body, ["issuer_digest", "subject_digest"]) && hash(body.issuer_digest) && hash(body.subject_digest);
    case "get_link": return fields(body, ["id"]) && id(body.id);
    case "list_links": return fields(body, ["offset"]) && integer(body.offset) && body.offset <= 999999;
    case "put_link": return fields(body, ["link", "actor", "now"]) && validLink(body.link) && text(body.actor) && integer(body.now);
    case "deactivate_link": return fields(body, ["id", "actor", "now"]) && id(body.id) && text(body.actor) && integer(body.now);
    case "audit": return fields(body, ["issuer_digest", "account", "outcome", "now"]) && hash(body.issuer_digest)
      && (body.account === null || text(body.account)) && OUTCOMES.has(body.outcome) && integer(body.now);
    default: return false;
  }
}

async function ready(db) {
  // Verify all columns before any mutation, including the audit destination.
  for (const query of ["SELECT state_digest,nonce_digest,recipient_digest,created_at,expires_at,claimed_at FROM saml_requests LIMIT 0",
    `SELECT ${LINK_COLUMNS} FROM saml_subject_links LIMIT 0`, "SELECT id,issuer_digest,account,actor_digest,outcome,occurred_at FROM saml_audit LIMIT 0",
    "SELECT username,revoked_at FROM control_users LIMIT 0"]) await db.prepare(query).all();
}

async function putLink(db, body) {
  const link = body.link;
  const actor = await actorDigest(body.actor);
  const account = await db.prepare("SELECT username FROM control_users WHERE username=? AND revoked_at IS NULL").bind(link.account).first();
  if (!account) return reply({ error: "saml_subject_unlinked" }, 403);
  const results = await db.batch([
    db.prepare(`INSERT INTO saml_subject_links(${LINK_COLUMNS})
      SELECT ?,?,?,?,?,?,?,1,?,? FROM control_users WHERE username=? AND revoked_at IS NULL
      ON CONFLICT(id) DO UPDATE SET account=excluded.account,org_id=excluded.org_id,team_id=excluded.team_id,
      grants_revision=excluded.grants_revision,active=1,updated_at=excluded.updated_at
      WHERE saml_subject_links.issuer_digest=excluded.issuer_digest AND saml_subject_links.subject_digest=excluded.subject_digest`)
      .bind(link.id, link.issuer_digest, link.subject_digest, link.account, link.org_id, link.team_id, link.grants_revision, body.now, body.now, link.account),
    db.prepare(`INSERT INTO saml_audit(id,issuer_digest,account,actor_digest,outcome,occurred_at)
      SELECT ?,issuer_digest,account,?,'link_put',? FROM saml_subject_links
      WHERE id=? AND issuer_digest=? AND subject_digest=? AND account=? AND updated_at=? AND active=1`)
      .bind(crypto.randomUUID(), actor, body.now, link.id, link.issuer_digest, link.subject_digest, link.account, body.now)
  ]);
  if (results[0].meta.changes !== 1 || results[1].meta.changes !== 1) return reply({ error: "saml_link_conflict" }, 409);
  return reply({ link: await db.prepare(`SELECT ${LINK_COLUMNS} FROM saml_subject_links WHERE id=?`).bind(link.id).first() });
}

async function deactivateLink(db, body) {
  const actor = await actorDigest(body.actor);
  const results = await db.batch([
    db.prepare(`INSERT INTO saml_audit(id,issuer_digest,account,actor_digest,outcome,occurred_at)
      SELECT ?,issuer_digest,account,?,'link_deactivated',? FROM saml_subject_links WHERE id=? AND active=1`)
      .bind(crypto.randomUUID(), actor, body.now, body.id),
    db.prepare("UPDATE saml_subject_links SET active=0,updated_at=? WHERE id=? AND active=1").bind(body.now, body.id)
  ]);
  return reply({ deactivated: results[1].meta.changes === 1 });
}

async function execute(db, body) {
  switch (body.operation) {
    case "ready": return reply({ ready: true });
    case "create_request": {
      const result = await db.prepare("INSERT INTO saml_requests(state_digest,nonce_digest,recipient_digest,created_at,expires_at) VALUES(?,?,?,?,?)")
        .bind(body.state_digest, body.nonce_digest, body.recipient_digest, body.now, body.expires_at).run();
      return reply({ created: result.meta.changes === 1 });
    }
    case "claim_request": {
      const result = await db.prepare(`UPDATE saml_requests SET claimed_at=? WHERE state_digest=? AND nonce_digest=?
        AND recipient_digest=? AND claimed_at IS NULL AND expires_at>? AND created_at<=?`)
        .bind(body.now, body.state_digest, body.nonce_digest, body.recipient_digest, body.now, body.now + 5).run();
      return reply({ claimed: result.meta.changes === 1 });
    }
    case "lookup_link": return reply({ link: await db.prepare(`SELECT ${LINK_COLUMNS} FROM saml_subject_links
      WHERE issuer_digest=? AND subject_digest=? AND active=1`).bind(body.issuer_digest, body.subject_digest).first() });
    case "get_link": return reply({ link: await db.prepare(`SELECT ${LINK_COLUMNS} FROM saml_subject_links WHERE id=?`).bind(body.id).first() });
    case "list_links": return reply({ links: (await db.prepare(`SELECT ${LINK_COLUMNS} FROM saml_subject_links ORDER BY id LIMIT 100 OFFSET ?`).bind(body.offset).all()).results });
    case "put_link": return putLink(db, body);
    case "deactivate_link": return deactivateLink(db, body);
    case "audit": {
      const result = await db.prepare("INSERT INTO saml_audit(id,issuer_digest,account,outcome,occurred_at) VALUES(?,?,?,?,?)")
        .bind(crypto.randomUUID(), body.issuer_digest, body.account, body.outcome, body.now).run();
      return reply({ recorded: result.meta.changes === 1 });
    }
    default: return reply({ error: "saml_request_invalid" }, 400);
  }
}

/** Register this handler at handleManagedStateRequest's fixed SAML domain. */
export async function handleSamlIdentityRequest(request, env) {
  const url = new URL(request.url);
  if (url.origin !== "http://intelligence.internal" || url.pathname !== PATH || url.search || url.hash
    || url.username || url.password || request.method !== "POST" || !enabled(env)) return reply({ error: "not_found" }, 404);
  let body;
  try { body = await bodyDocument(request); }
  catch { return reply({ error: "saml_request_invalid" }, 400); }
  if (!validOperation(body)) return reply({ error: "saml_request_invalid" }, 400);
  if (!env.INTELLIGENCE_DB) return reply({ error: "saml_storage_unavailable" }, 503);
  try {
    await ready(env.INTELLIGENCE_DB);
    return await execute(env.INTELLIGENCE_DB, body);
  } catch (error) {
    const conflict = /UNIQUE constraint failed/.test(String(error?.message));
    return reply({ error: conflict ? "saml_link_conflict" : "saml_storage_unavailable" }, conflict ? 409 : 503);
  }
}
