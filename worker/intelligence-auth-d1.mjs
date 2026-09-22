const scopesAllowed = new Set(["chat", "models", "audio", "embeddings"]);
const idPattern = /^integration:[a-z][a-z0-9_-]{0,63}$/;
const prefixPattern = /^mllm_intelligence_[A-Za-z0-9_-]{16}$/;
const hashPattern = /^scrypt:32768:8:1\$[A-Za-z0-9]{8,32}\$[a-f0-9]{128}$/;
const reply = (value, status = 200) => Response.json(value.error
  ? {version:1, error:{code:value.error, message:"Integration credential operation failed"}}
  : value, {status, headers:{"cache-control":"no-store"}});
const fields = (body, names) => Object.keys(body).every(key => names.includes(key))
  && names.every(key => Object.hasOwn(body, key));
const validPrefix = value => typeof value === "string" && prefixPattern.test(value);
const validCredential = body => validPrefix(body.keyPrefix)
  && typeof body.keyHash === "string" && hashPattern.test(body.keyHash);
async function boundedBody(request) {
  if (!request.body) throw new Error("Missing body");
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 4096) { void reader.cancel().catch(() => {}); throw new Error("Oversized body"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder("utf-8", {fatal:true}).decode(bytes);
}

export async function handleIntelligenceAuthRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal"
    || url.pathname !== "/v1/auth" || url.search || url.hash || url.username || url.password)
    return reply({error: "not_found"}, 404);
  if (request.headers.get("content-type")?.split(";",1)[0].trim().toLowerCase() !== "application/json")
    return reply({error:"invalid_request"}, 400);
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > 4096))
    return reply({error:"invalid_request"}, 400);
  if (!env.INTELLIGENCE_DB) return reply({error: "storage_unavailable"}, 503);
  let body;
  try {
    const text = await boundedBody(request);
    if (text.length > 4096) return reply({error: "invalid_request"}, 400);
    body = JSON.parse(text);
    if (!body || Array.isArray(body) || typeof body !== "object" || body.version !== 1)
      return reply({error: "invalid_request"}, 400);
  } catch { return reply({error: "invalid_request"}, 400); }
  const db = env.INTELLIGENCE_DB;
  try {
    if (body.operation === "lookup") {
      if (!fields(body, ["version", "operation", "keyPrefix"]) || !validPrefix(body.keyPrefix))
        return reply({error: "invalid_request"}, 400);
      const row = await db.prepare(`SELECT p.id, p.scopes, p.version, p.created_at, p.revoked_at,
        c.key_prefix, c.key_hash FROM intelligence_credentials c
        JOIN intelligence_principals p ON p.id=c.principal_id AND p.version=c.version
        WHERE c.key_prefix=?`).bind(body.keyPrefix).first();
      return reply({version: 1, principal: row ? {
        id: row.id, scopes: JSON.parse(row.scopes), credentialVersion: row.version,
        createdAt: row.created_at, revokedAt: row.revoked_at,
        keyPrefix: row.key_prefix, keyHash: row.key_hash
      } : null});
    }
    if (typeof body.principalId !== "string" || !idPattern.test(body.principalId)) return reply({error: "invalid_request"}, 400);
    const now = new Date().toISOString();
    if (body.operation === "provision") {
      if (!fields(body, ["version", "operation", "principalId", "keyPrefix", "keyHash", "scopes"])
        || !validCredential(body) || !Array.isArray(body.scopes) || !body.scopes.length
        || body.scopes.length > 4 || new Set(body.scopes).size !== body.scopes.length
        || body.scopes.some(scope => !scopesAllowed.has(scope)))
        return reply({error: "invalid_request"}, 400);
      await db.batch([
        db.prepare("INSERT INTO intelligence_principals(id,scopes,version,created_at) VALUES(?,?,1,?)")
          .bind(body.principalId, JSON.stringify(body.scopes), now),
        db.prepare("INSERT INTO intelligence_credentials(principal_id,version,key_prefix,key_hash) VALUES(?,1,?,?)")
          .bind(body.principalId, body.keyPrefix, body.keyHash)
      ]);
      return reply({version: 1, credentialVersion: 1}, 201);
    }
    if (!Number.isSafeInteger(body.expectedVersion) || body.expectedVersion < 1)
      return reply({error: "invalid_request"}, 400);
    if (body.operation === "rotate") {
      if (!fields(body, ["version", "operation", "principalId", "expectedVersion", "keyPrefix", "keyHash"])
        || !validCredential(body)) return reply({error: "invalid_request"}, 400);
      const results = await db.batch([
        db.prepare(`INSERT INTO intelligence_credentials(principal_id,version,key_prefix,key_hash)
          SELECT id,version+1,?,? FROM intelligence_principals
          WHERE id=? AND version=? AND revoked_at IS NULL`)
          .bind(body.keyPrefix, body.keyHash, body.principalId, body.expectedVersion),
        db.prepare(`UPDATE intelligence_principals SET version=version+1
          WHERE id=? AND version=? AND revoked_at IS NULL
          AND EXISTS(SELECT 1 FROM intelligence_credentials WHERE principal_id=? AND version=? AND key_prefix=?)`)
          .bind(body.principalId, body.expectedVersion, body.principalId, body.expectedVersion + 1, body.keyPrefix)
      ]);
      return results[0].meta.changes === 1 && results[1].meta.changes === 1
        ? reply({version: 1, credentialVersion: body.expectedVersion + 1})
        : reply({error: "credential_conflict"}, 409);
    }
    if (body.operation === "revoke") {
      if (!fields(body, ["version", "operation", "principalId", "expectedVersion"]))
        return reply({error: "invalid_request"}, 400);
      const result = await db.prepare(`UPDATE intelligence_principals SET revoked_at=?
        WHERE id=? AND version=? AND revoked_at IS NULL`).bind(now, body.principalId, body.expectedVersion).run();
      return result.meta.changes === 1 ? reply({version: 1, revoked: true}) : reply({error: "credential_conflict"}, 409);
    }
    return reply({error: "invalid_request"}, 400);
  } catch (error) {
    // Unique constraints retain old prefixes and prevent reprovisioning or key reuse.
    return reply({error: /UNIQUE constraint failed/.test(String(error?.message))
      ? "credential_conflict" : "storage_unavailable"}, /UNIQUE constraint failed/.test(String(error?.message)) ? 409 : 503);
  }
}
