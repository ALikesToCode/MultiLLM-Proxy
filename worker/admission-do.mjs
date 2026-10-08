import { boundedBody } from "./control-users-d1.mjs";

const HASH = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const GROUP = /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/;
const LEASE = /^[0-9a-f]{32}$/;
const LEASE_MS = 30_000;
const RENEW_MS = 10_000;
const MAX_OUTSTANDING = 10_000;
const MAX_DEADLINE_MS = 86_400_000;
const PRIVATE_URL = "http://admission.internal/v1/admission";
let warned = false;
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const limit = value => Number.isSafeInteger(value) && value >= 0 && value <= MAX_OUTSTANDING;
const fields = (body, names) => object(body) && Object.keys(body).length === names.length && names.every(key => Object.hasOwn(body, key));
const matches = (pattern, value) => typeof value === "string" && pattern.test(value);

export function admissionSettings(env = {}) {
  const flag = String(env.ADMISSION_ENABLED ?? "").trim().toLowerCase();
  if (["", "false", "0"].includes(flag)) return { enabled: false };
  try {
    if (!["true", "1"].includes(flag)) throw Error("flag");
    const limits = JSON.parse(env.ADMISSION_LIMITS_JSON?.trim() || "{}");
    if (!object(limits) || Object.keys(limits).some(key => !["principal", "model_groups"].includes(key))
      || (Object.hasOwn(limits, "principal") && !limit(limits.principal))
      || (Object.hasOwn(limits, "model_groups") && (!object(limits.model_groups)
        || Object.keys(limits.model_groups).length > 256
        || Object.entries(limits.model_groups).some(([key, value]) => !GROUP.test(key) || !limit(value))))) throw Error("limits");
    return { enabled: true, principal: limits.principal ?? 0, groups: limits.model_groups ?? {} };
  } catch {
    if (!warned) { warned = true; console.warn("Invalid admission configuration; admission is disabled."); }
    return { enabled: false };
  }
}
const groupLimit = (settings, group) => Object.hasOwn(settings.groups, group) ? settings.groups[group] : 0;
const unlimited = (settings, group) => !settings.principal && !groupLimit(settings, group);
const validIdentity = value => object(value) && matches(HASH, value.principal_hash) && matches(GROUP, value.model_group)
  && matches(ID, value.request_id) && Number.isSafeInteger(value.deadline_ms) && value.deadline_ms > 0;
function validOperation(body) {
  const names = ["version", "operation", "principal_hash", "model_group", "request_id", "deadline_ms"];
  if (["renew", "release"].includes(body?.operation)) names.push("lease_id");
  return fields(body, names) && body.version === 1 && ["acquire", "renew", "release"].includes(body.operation)
    && validIdentity(body) && (body.operation === "acquire" || matches(LEASE, body.lease_id));
}
const reply = (body, status = 200, retry = null) => Response.json({ version: 1, ...body }, {
  status, headers: { "cache-control": "no-store", ...(retry === null ? {} : { "Retry-After": String(retry) }) },
});
const failure = (code, status, retry = null) => reply({ error: { code, message: "Concurrency admission failed." } }, status, retry);
const leaseReply = row => reply({ lease: { lease_id: row.lease_id, expires_at: row.expires_at } });

/** Private SQLite authority. Construction and disabled calls perform no storage work. */
export class AdmissionCoordinator {
  constructor(ctx, env, clock = Date.now) {
    this.storage = ctx.storage;
    this.env = env;
    this.clock = clock;
    this.ready = false;
  }

  rows(sql, ...args) { return this.storage.sql.exec(sql, ...args).toArray(); }

  initialize() {
    if (this.ready) return;
    this.storage.transactionSync(() => {
      this.rows(`CREATE TABLE IF NOT EXISTS admission_leases (
        lease_id TEXT PRIMARY KEY, principal_hash TEXT NOT NULL, model_group TEXT NOT NULL,
        request_id TEXT NOT NULL, deadline_ms INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        UNIQUE(principal_hash, request_id))`);
      this.rows("CREATE INDEX IF NOT EXISTS admission_expiry ON admission_leases(expires_at)");
      this.rows("CREATE INDEX IF NOT EXISTS admission_scope ON admission_leases(principal_hash, model_group, expires_at)");
    });
    this.ready = true;
  }

  async fetch(request) {
    if (request.url !== PRIVATE_URL || request.method !== "POST") return failure("not_found", 404);
    const settings = admissionSettings(this.env);
    if (!settings.enabled) return reply({ lease: null });
    let body;
    try { body = JSON.parse(await boundedBody(request, 4096)); } catch { return failure("invalid_request", 400); }
    if (!validOperation(body)) return failure("invalid_request", 400);
    if (body.operation === "acquire" && unlimited(settings, body.model_group)) return reply({ lease: null });
    try {
      this.initialize();
      return this.storage.transactionSync(() => this.operate(body, settings));
    } catch { return failure("admission_unavailable", 503); }
  }

  operate(body, settings) {
    const now = this.clock();
    this.rows("DELETE FROM admission_leases WHERE expires_at <= ?", now);
    if (body.operation === "acquire") return this.acquire(body, settings, now);
    const [row] = this.rows("SELECT * FROM admission_leases WHERE lease_id = ?", body.lease_id);
    if (!row) return body.operation === "release" ? reply({ released: false }) : failure("admission_lease_expired", 409);
    if (["principal_hash", "model_group", "request_id", "deadline_ms"].some(key => row[key] !== body[key])) {
      return failure("admission_identity_mismatch", 403);
    }
    if (body.operation === "release") {
      this.rows("DELETE FROM admission_leases WHERE lease_id = ?", body.lease_id);
      return reply({ released: true });
    }
    row.expires_at = Math.min(now + LEASE_MS, row.deadline_ms);
    this.rows("UPDATE admission_leases SET expires_at = ? WHERE lease_id = ?", row.expires_at, row.lease_id);
    return leaseReply(row);
  }

  acquire(body, settings, now) {
    if (body.deadline_ms <= now || body.deadline_ms > now + MAX_DEADLINE_MS) return failure("admission_deadline_invalid", 400);
    const [existing] = this.rows("SELECT * FROM admission_leases WHERE principal_hash = ? AND request_id = ?",
      body.principal_hash, body.request_id);
    if (existing) {
      if (existing.model_group !== body.model_group || existing.deadline_ms !== body.deadline_ms) {
        return failure("admission_identity_mismatch", 403);
      }
      return leaseReply(existing);
    }
    const scopes = [
      ["", [], MAX_OUTSTANDING],
      ["WHERE principal_hash = ?", [body.principal_hash], settings.principal],
      ["WHERE principal_hash = ? AND model_group = ?", [body.principal_hash, body.model_group], groupLimit(settings, body.model_group)],
    ];
    for (const [where, args, maximum] of scopes) {
      if (!maximum) continue;
      const [count] = this.rows(`SELECT COUNT(*) AS n, MIN(expires_at) AS next_expiry FROM admission_leases ${where}`, ...args);
      if (count.n >= maximum) return failure("admission_denied", 429, Math.max(1, Math.ceil((count.next_expiry - now) / 1000)));
    }
    const row = { ...body, lease_id: crypto.randomUUID().replaceAll("-", ""), expires_at: Math.min(now + LEASE_MS, body.deadline_ms) };
    this.rows("INSERT INTO admission_leases VALUES (?, ?, ?, ?, ?, ?)", row.lease_id, row.principal_hash,
      row.model_group, row.request_id, row.deadline_ms, row.expires_at);
    return leaseReply(row);
  }

  async alarm() {
    // Expiry is pruned on operations; no alarms are scheduled, including while disabled.
    if (!admissionSettings(this.env).enabled || !this.ready) return;
    this.rows("DELETE FROM admission_leases WHERE expires_at <= ?", this.clock());
  }
}

async function authorityCall(body, env) {
  let timer;
  try {
    const shard = parseInt(body.principal_hash.slice(0, 2), 16) % 64;
    const stub = env.ADMISSION_COORDINATOR.getByName(`admission-${shard}`);
    return await Promise.race([
      stub.fetch(new Request(PRIVATE_URL, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(body), signal: AbortSignal.timeout(5000) })),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new AdmissionError()), 5000); }),
    ]);
  } catch { return failure("admission_unavailable", 503); }
  finally { clearTimeout(timer); }
}

/** Only the authenticated Container egress dispatcher calls this route. */
export async function handleAdmissionRequest(request, env) {
  if (request.url !== "http://intelligence.internal/v1/admission" || request.method !== "POST") return failure("not_found", 404);
  const settings = admissionSettings(env);
  if (!settings.enabled) return reply({ lease: null });
  let body;
  try { body = JSON.parse(await boundedBody(request, 4096)); } catch { return failure("invalid_request", 400); }
  if (!validOperation(body)) return failure("invalid_request", 400);
  if (body.operation === "acquire" && unlimited(settings, body.model_group)) return reply({ lease: null });
  return authorityCall(body, env);
}

export class AdmissionError extends Error {
  constructor(code = "admission_unavailable", status = 503, retryAfter = null) {
    super("Concurrency admission failed.");
    this.code = code;
    this.status = status;
    this.retryAfter = retryAfter;
  }
  response() { return failure(this.code, this.status, this.retryAfter); }
}

async function call(body, env) {
  const response = await authorityCall(body, env);
  try {
    const payload = JSON.parse(await boundedBody(response, 4096));
    if (payload.version !== 1) throw Error("version");
    if (response.status !== 200) {
      const retry = Number(response.headers.get("Retry-After"));
      throw new AdmissionError(response.status === 429 ? "admission_denied" : "admission_unavailable",
        response.status === 429 ? 429 : 503, response.status === 429 && Number.isSafeInteger(retry) && retry > 0 ? retry : null);
    }
    return payload;
  } catch (error) {
    if (error instanceof AdmissionError) throw error;
    throw new AdmissionError();
  }
}

class AdmissionLease {
  constructor(identity, env, value, options) {
    this.identity = identity;
    this.env = env;
    this.clock = options.clock ?? Date.now;
    this.onLost = options.onLost ?? (() => {});
    this.closed = false;
    this.lost = null;
    this.renewing = false;
    this.value = value;
    this.interval = setInterval(() => { void this.renew(); }, RENEW_MS);
    this.timer = setTimeout(() => { void this.lose(new AdmissionError("admission_deadline_exceeded")); },
      Math.max(0, Math.min(value.expires_at, identity.deadline_ms) - this.clock()));
    this.interval.unref?.();
    this.timer.unref?.();
  }
  async renew() {
    if (this.closed || this.renewing) return;
    this.renewing = true;
    try {
      const payload = await call({ version: 1, operation: "renew", ...this.identity, lease_id: this.value.lease_id }, this.env);
      if (this.closed) return;
      this.validate(payload.lease);
      this.value = payload.lease;
      clearTimeout(this.timer);
      this.timer = setTimeout(() => { void this.lose(new AdmissionError("admission_deadline_exceeded")); },
        Math.max(0, Math.min(this.value.expires_at, this.identity.deadline_ms) - this.clock()));
      this.timer.unref?.();
    } catch (error) { await this.lose(error); }
    finally { this.renewing = false; }
  }
  validate(value) {
    if (!object(value) || !matches(LEASE, value.lease_id) || value.lease_id !== this.value.lease_id
      || !Number.isSafeInteger(value.expires_at) || value.expires_at <= this.clock()
      || value.expires_at > Math.min(this.clock() + LEASE_MS, this.identity.deadline_ms)) throw new AdmissionError();
  }
  check() {
    if (this.lost) throw this.lost;
    if (this.closed || this.clock() >= Math.min(this.value.expires_at, this.identity.deadline_ms)) throw new AdmissionError();
  }
  async lose(error) {
    if (this.closed) return;
    this.lost = error instanceof AdmissionError ? error : new AdmissionError();
    await Promise.allSettled([this.release(), Promise.resolve().then(() => this.onLost(this.lost))]);
  }
  async release() {
    if (this.closed) return this.releasePromise;
    this.closed = true;
    clearInterval(this.interval);
    clearTimeout(this.timer);
    this.releasePromise = (async () => {
      try { await call({ version: 1, operation: "release", ...this.identity, lease_id: this.value.lease_id }, this.env); }
      catch { /* An uncertain release is never replayed; the persisted lease expires. */ }
    })();
    return this.releasePromise;
  }
}

/** Identity comes from authentication and authorized routing, never request headers. */
export async function acquireAdmission(identity, env, options = {}) {
  const settings = admissionSettings(env);
  if (!settings.enabled || (!settings.principal && Object.values(settings.groups).every(value => !value))) return null;
  if (!validIdentity(identity) || !fields(identity, ["principal_hash", "model_group", "request_id", "deadline_ms"])) {
    throw new AdmissionError("admission_identity_invalid", 403);
  }
  if (unlimited(settings, identity.model_group)) return null;
  const payload = await call({ version: 1, operation: "acquire", ...identity }, env);
  const value = payload.lease;
  if (!object(value) || !matches(LEASE, value.lease_id) || !Number.isSafeInteger(value.expires_at)
    || value.expires_at <= (options.clock ?? Date.now)()
    || value.expires_at > Math.min((options.clock ?? Date.now)() + LEASE_MS, identity.deadline_ms)) throw new AdmissionError();
  return new AdmissionLease(identity, env, value, options);
}

export async function runWithAdmission(identity, env, dispatch, options = {}) {
  let reader;
  let response;
  const lease = await acquireAdmission(identity, env, { ...options, onLost: async error => {
    try { await reader?.cancel(error); } finally { await options.onLost?.(error); }
  } });
  if (!lease) return dispatch();
  let aborted = false;
  const abort = () => { aborted = true; void lease.lose(new AdmissionError("admission_canceled")); void reader?.cancel().catch(() => {}); };
  options.signal?.addEventListener("abort", abort, { once: true });
  const finish = async () => { options.signal?.removeEventListener("abort", abort); await lease.release(); };
  try {
    if (options.signal?.aborted) abort();
    lease.check();
    response = await dispatch(lease);
    if (aborted) throw new AdmissionError("admission_canceled");
    lease.check();
    if (!response.body) { await finish(); return response; }
    reader = response.body.getReader();
    const body = new ReadableStream({
      async pull(controller) {
        try {
          lease.check();
          const { done, value } = await reader.read();
          lease.check();
          if (done) { await finish(); controller.close(); }
          else controller.enqueue(value);
        } catch (error) {
          controller.error(error);
          try { await reader.cancel(); } finally { await finish(); }
        }
      },
      async cancel(reason) { try { await reader.cancel(reason); } finally { await finish(); } },
    }, { highWaterMark: 0 });
    return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
  } catch (error) {
    try { if (reader) await reader.cancel(); else await response?.body?.cancel(); } finally { await finish(); }
    throw error;
  }
}
