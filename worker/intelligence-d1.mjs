const MAX_BODY_BYTES = 256 * 1024;
const DAY_MS = 24 * 60 * 60 * 1000;
const POLICY_INTEGER_MAX = 2 ** 31 - 1;
const KINDS = new Set(["chat", "transcriptions", "speech", "embeddings"]);
const FIELDS = {
  policy: ["version", "operation"],
  seed: ["version", "operation", "policy"],
  reserve: ["version", "operation", "id", "principal", "amount", "kind"],
  settle: ["version", "operation", "id", "used", "complete"],
};

class StoreError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function invalid() {
  return new StoreError(400, "invalid_store_request", "The store request is invalid.");
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function integer(value, minimum = 1, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function reservationId(value) {
  return typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
}

function principal(value) {
  if (typeof value !== "string") return false;
  const characters = [...value];
  return characters.length > 0 && characters.length <= 256
    && characters.every((character) => character.charCodeAt(0) >= 32 && character.charCodeAt(0) !== 127);
}

function reply(body, status = 200) {
  return Response.json({ version: 1, ...body }, {
    status,
    headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

async function readBody(request) {
  const tooLarge = () => new StoreError(413, "store_request_too_large", "The store request is too large.");
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BODY_BYTES)) {
    void request.body?.cancel().catch(() => {});
    throw tooLarge();
  }
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    throw new StoreError(415, "unsupported_store_content_type", "The store accepts JSON requests only.");
  }
  if (!request.body) throw invalid();
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  let done = false;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) { done = true; break; }
      size += item.value.byteLength;
      if (size > MAX_BODY_BYTES) throw tooLarge();
      chunks.push(item.value);
    }
  } finally {
    if (!done) void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw invalid(); }
}

function validateRequest(body) {
  if (!record(body) || body.version !== 1 || typeof body.operation !== "string" || !Object.hasOwn(FIELDS, body.operation)) throw invalid();
  if (Object.keys(body).some((key) => !FIELDS[body.operation].includes(key))) throw invalid();
  if (["reserve", "settle"].includes(body.operation) && !reservationId(body.id)) throw invalid();
  if (body.operation === "reserve" && (
    !integer(body.amount) || !KINDS.has(body.kind) || (body.kind !== "chat" && body.amount !== 1)
    || !principal(body.principal)
  )) throw invalid();
  if (body.operation === "settle" && (!integer(body.used, 0) || typeof body.complete !== "boolean")) throw invalid();
  return body;
}

// Python validates candidate eligibility. These are the limits the ledger itself enforces,
// and must be checked independently before any quota calculation or policy seed.
function validatePolicy(policy, status = 400) {
  const fail = () => { throw new StoreError(status, "invalid_intelligence_policy", "The gateway allowance policy is invalid."); };
  if (!record(policy) || policy.version !== 1 || typeof policy.enabled !== "boolean") fail();
  for (const field of ["principal_daily_tokens", "global_daily_tokens", "max_total_tokens", "max_inflight"]) {
    if (!integer(policy[field], 1, POLICY_INTEGER_MAX)) fail();
  }
  if (!record(policy.media) || Object.keys(policy.media).some((kind) => kind === "chat" || !KINDS.has(kind))) fail();
  for (const settings of Object.values(policy.media)) {
    if (!record(settings)) fail();
    for (const field of ["principal_daily_requests", "daily_requests"]) {
      if (!integer(settings[field], 1, POLICY_INTEGER_MAX)) fail();
    }
  }
  return policy;
}

async function storedPolicy(db) {
  const row = await db.prepare("SELECT document FROM intelligence_policy WHERE id = 1").first();
  if (!row) return null;
  if (typeof row.document !== "string" || new TextEncoder().encode(row.document).length > MAX_BODY_BYTES) {
    throw new StoreError(503, "invalid_intelligence_policy", "The gateway allowance policy is invalid.");
  }
  let value;
  try { value = JSON.parse(row.document); }
  catch { throw new StoreError(503, "invalid_intelligence_policy", "The gateway allowance policy is invalid."); }
  return { document: row.document, policy: validatePolicy(value, 503) };
}

async function seed(db, body) {
  const policy = validatePolicy(body.policy);
  const result = await db.prepare("INSERT OR IGNORE INTO intelligence_policy (id, document) VALUES (1, ?)")
    .bind(JSON.stringify(policy)).run();
  if (!result.success) throw new Error("store unavailable");
  return { inserted: result.meta.changes === 1 };
}

const RESERVE_SQL = `
  INSERT INTO intelligence_reservations
    (id, principal, kind, created_at, reserved, charged, state)
  SELECT ?1, ?2, ?3, ?4, ?5, ?5, 'pending'
  WHERE EXISTS (SELECT 1 FROM intelligence_policy WHERE id = 1 AND document = ?6)
    AND COALESCE((SELECT SUM(charged) FROM intelligence_reservations
      WHERE kind = ?3 AND principal = ?2 AND (created_at >= ?7 OR state != 'settled')), 0) <= ?8 - ?5
    AND COALESCE((SELECT SUM(charged) FROM intelligence_reservations
      WHERE kind = ?3 AND (created_at >= ?7 OR state != 'settled')), 0) <= ?9 - ?5
    AND (SELECT COUNT(*) FROM intelligence_reservations WHERE kind = ?3 AND state = 'pending') < ?10
  ON CONFLICT(id) DO NOTHING`;

async function reserve(db, body) {
  const stored = await storedPolicy(db);
  if (!stored) throw new StoreError(503, "intelligence_policy_unavailable", "The gateway allowance policy is unavailable.");
  const { policy, document } = stored;
  const media = policy.media[body.kind];
  if ((body.kind === "chat" && !policy.enabled) || (body.kind !== "chat" && !media)) {
    throw new StoreError(503, "intelligence_disabled", "This gateway operation is not enabled.");
  }
  const principalLimit = body.kind === "chat" ? policy.principal_daily_tokens : media.principal_daily_requests;
  const globalLimit = body.kind === "chat" ? policy.global_daily_tokens : media.daily_requests;
  if (body.kind === "chat" && body.amount > policy.max_total_tokens) {
    throw new StoreError(429, "allowance_exhausted", "The request exceeds the available gateway allowance.");
  }
  // Clock and quota inputs come from the Worker and stored policy, never the caller.
  // The insert's reads run in its write transaction; competing replicas cannot both
  // observe the same remaining allowance. The document guard closes a policy-change race.
  const now = Date.now();
  const results = await db.batch([
    db.prepare(RESERVE_SQL).bind(body.id, body.principal, body.kind, now, body.amount,
      document, now - DAY_MS, principalLimit, globalLimit, policy.max_inflight),
    db.prepare("SELECT principal, kind, reserved, state FROM intelligence_reservations WHERE id = ?").bind(body.id),
    db.prepare("SELECT document FROM intelligence_policy WHERE id = 1"),
  ]);
  if (results.some((result) => !result.success)) throw new Error("store unavailable");
  const row = results[1].results[0];
  if (row) {
    if (row.principal !== body.principal || row.kind !== body.kind || row.reserved !== body.amount || row.state !== "pending") {
      throw new StoreError(409, "reservation_conflict", "The reservation identifier already names different work.");
    }
    return { id: body.id };
  }
  if (results[2].results[0]?.document !== document) {
    throw new StoreError(409, "intelligence_policy_changed", "The gateway allowance policy changed before admission.");
  }
  throw new StoreError(429, "allowance_exhausted", "The request exceeds the available gateway allowance.");
}

async function settle(db, body) {
  // Unknown outcomes keep their full reservation indefinitely. Repeating a completed
  // settlement cannot lower a charge or release an outcome that requires reconciliation.
  const result = await db.prepare(`UPDATE intelligence_reservations
    SET charged = CASE WHEN ?2 = 1 THEN ?3 ELSE MAX(charged, ?3) END,
        state = CASE WHEN ?2 = 1 THEN 'settled' ELSE 'unknown' END
    WHERE id = ?1 AND state = 'pending'`).bind(body.id, body.complete ? 1 : 0, body.used).run();
  if (!result.success) throw new Error("store unavailable");
  return { settled: result.meta.changes === 1 };
}

/** Private container outbound handler; the public Worker must never route requests here. */
export async function handleIntelligenceStoreRequest(request, env) {
  try {
    const url = new URL(request.url);
    if (url.origin !== "http://intelligence.internal" || url.pathname !== "/v1/store" || url.search || url.hash
      || url.username || url.password) {
      throw new StoreError(404, "store_route_not_found", "The store route is unavailable.");
    }
    if (request.method !== "POST") throw new StoreError(405, "store_method_not_allowed", "The store requires POST.");
    const body = validateRequest(await readBody(request));
    const db = env.INTELLIGENCE_DB;
    if (!db || typeof db.prepare !== "function" || typeof db.batch !== "function") {
      throw new StoreError(503, "intelligence_store_unavailable", "The gateway allowance store is unavailable.");
    }
    let result;
    if (body.operation === "policy") result = { policy: (await storedPolicy(db))?.policy ?? null };
    else if (body.operation === "seed") result = await seed(db, body);
    else if (body.operation === "reserve") result = await reserve(db, body);
    else result = await settle(db, body);
    return reply(result);
  } catch (error) {
    const failure = error instanceof StoreError ? error
      : new StoreError(503, "intelligence_store_unavailable", "The gateway allowance store is unavailable.");
    return reply({ error: { code: failure.code, message: failure.message } }, failure.status);
  }
}
