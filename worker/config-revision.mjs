/** Revision metadata and atomic writes behind the fixed private control-state endpoint. */

const DOMAINS = Object.freeze(["auto_routes", "model_overrides", "provider_catalog", "key_controls", "model_grants"]);
const warned = new Set();
function malformed(name) {
  if (!warned.has(name)) {
    warned.add(name);
    console.warn(`Invalid ${name}; configuration revision sync disabled`);
  }
}

export function revisionSyncSettings(env) {
  const flag = String(env.CONFIG_REVISION_SYNC_ENABLED || "").trim().toLowerCase();
  if (!["", "0", "false", "no", "off", "1", "true", "yes", "on"].includes(flag)) {
    malformed("CONFIG_REVISION_SYNC_ENABLED");
    return { enabled: false, ttl: 30, securityTtl: 5 };
  }
  const result = { enabled: ["1", "true", "yes", "on"].includes(flag), ttl: 30, securityTtl: 5 };
  if (!result.enabled) return result;
  for (const [name, field, maximum] of [["CONFIG_SYNC_TTL_SECONDS", "ttl", 3600], ["CONFIG_SECURITY_TTL_SECONDS", "securityTtl", 5]]) {
    const value = String(env[name] || "").trim();
    if (!value) continue;
    const number = Number(value);
    if (!/^(?:\d+(?:\.\d*)?|\.\d+)$/.test(value) || !Number.isFinite(number) || number < 1 || number > maximum) {
      malformed(name);
      return { enabled: false, ttl: 30, securityTtl: 5 };
    }
    result[field] = number;
  }
  return result;
}

export async function requireRevisionSchema(db) {
  await db.prepare("SELECT domain, revision, updated_at FROM control_revisions LIMIT 1").all();
}

/** Only trusted, fixed storage statements are accepted. D1 batch rolls back a failed CAS. */
export async function commitRevision(db, domain, statements, expectedRevision = null) {
  const domains = Array.isArray(domain) ? domain : [domain];
  if (!domains.length || new Set(domains).size !== domains.length
    || !domains.every(name => DOMAINS.includes(name) && name !== "auto_routes") || !statements.length
    || expectedRevision !== null && (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0)) {
    throw new Error("Invalid revision transaction");
  }
  await requireRevisionSchema(db);
  const now = new Date().toISOString();
  const batch = domains.flatMap(name => [
    db.prepare("INSERT OR IGNORE INTO control_revisions (domain, revision, updated_at) VALUES (?, 0, ?)").bind(name, now),
    db.prepare(`UPDATE control_revisions SET revision=revision+1, updated_at=?
      WHERE domain=? AND revision < 9007199254740991 ${expectedRevision === null ? "" : "AND revision=?"}`)
      .bind(...(expectedRevision === null ? [now, name] : [now, name, expectedRevision])),
    // A failed CAS aborts the entire batch before any configuration statement runs.
    db.prepare("INSERT INTO control_revisions (domain, revision, updated_at) SELECT ?, -1, ? WHERE changes() != 1").bind(name, now),
  ]);
  batch.push(...statements);
  try {
    await db.batch(batch);
    return true;
  } catch (error) {
    if (String(error?.message).includes("revision_cas_confirmed")) return false;
    throw error;
  }
}

export async function handleRevisionMetadata(db, body) {
  if (Object.keys(body).length !== 3 || body.version !== 1 || body.operation !== "revisions"
    || !Array.isArray(body.domains) || !body.domains.length || body.domains.length > DOMAINS.length
    || new Set(body.domains).size !== body.domains.length || !body.domains.every(name => DOMAINS.includes(name))) return null;
  await requireRevisionSchema(db);
  const statements = body.domains.map(domain => domain === "auto_routes"
    ? db.prepare("SELECT COALESCE((SELECT revision FROM config_snapshot_revisions WHERE domain='auto_routes'), 0) AS revision")
    : db.prepare("SELECT COALESCE((SELECT revision FROM control_revisions WHERE domain=?), 0) AS revision").bind(domain));
  const rows = await db.batch(statements);
  return Response.json({ version: 1, revisions: Object.fromEntries(body.domains.map((domain, index) => [domain, rows[index].results[0].revision])) },
    { headers: { "cache-control": "no-store" } });
}

/** Private auto-route dispatch injects its handler and bounded body reader. */
export async function handleRevisionedAutoRoutes(request, env, { handleAutoRoutesRequest, boundedBody }) {
  if (!revisionSyncSettings(env).enabled) return handleAutoRoutesRequest(request, env);
  const url = new URL(request.url);
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal" || url.pathname !== "/v1/auto-routes"
    || url.search || url.hash || url.username || url.password) return handleAutoRoutesRequest(request, env);
  try {
    if (!env.INTELLIGENCE_DB) throw new Error("Missing storage");
    await requireRevisionSchema(env.INTELLIGENCE_DB);
  } catch {
    return Response.json({ version: 1, error: { code: "config_revision_storage_unavailable", message: "Configuration revision storage is unavailable" } },
      { status: 503, headers: { "cache-control": "no-store" } });
  }
  if (["1", "true", "yes", "on"].includes(String(env.CONFIG_SNAPSHOTS_ENABLED || "").trim().toLowerCase())) {
    return handleAutoRoutesRequest(request, env);
  }
  // Reuse the snapshot counter only for a normal write, never snapshot operations.
  try {
    const body = JSON.parse(await boundedBody(request.clone(), 16384));
    if (body?.operation === "put") return handleAutoRoutesRequest(request, { ...env, CONFIG_SNAPSHOTS_ENABLED: "true" });
  } catch {
    // The original handler owns validation and the unchanged error envelope.
  }
  return handleAutoRoutesRequest(request, env);
}

const SECURITY_DOMAINS = new Set(["model_overrides", "key_controls", "model_grants"]);
const validMetadata = (value, domains) => value && typeof value === "object" && !Array.isArray(value)
  && Object.keys(value).length === domains.length && domains.every(domain => Object.hasOwn(value, domain)
    && Number.isSafeInteger(value[domain]) && value[domain] >= 0 && value[domain] <= 9007199254740991);

/** Native dispatch injects strict cache installers and calls the freshness guard. */
export class RevisionConsumer {
  constructor(env, { read, refreshers = {}, clock = () => performance.now() / 1000, jitter = Math.random } = {}) {
    this.settings = revisionSyncSettings(env);
    this.read = read || (async domains => {
      const response = await handleRevisionMetadata(env.INTELLIGENCE_DB, { version: 1, operation: "revisions", domains });
      return (await response.json()).revisions;
    });
    this.clock = clock;
    this.jitter = jitter;
    this.domains = Object.fromEntries(DOMAINS.map(domain => [domain, {
      refresh: refreshers[domain], security: SECURITY_DOMAINS.has(domain), revision: null, observed: null, checked: null, due: 0,
    }]));
    this.inFlight = null;
  }

  async tick() {
    if (!this.settings.enabled) return;
    if (this.inFlight) return this.inFlight;
    this.inFlight = this.poll();
    try { await this.inFlight; }
    finally { this.inFlight = null; }
  }

  async poll() {
    for (const security of [true, false]) await this.pollGroup(security);
  }

  async pollGroup(security) {
    const started = this.clock();
    const due = Object.keys(this.domains).filter(name => this.domains[name].security === security && started >= this.domains[name].due);
    if (!due.length) return;
    for (const name of due) {
      const ttl = security ? this.settings.securityTtl : this.settings.ttl;
      this.domains[name].due = started + ttl * (0.8 + 0.2 * Math.min(1, Math.max(0, this.jitter())));
    }
    let revisions;
    try {
      revisions = await this.read(due);
      if (!validMetadata(revisions, due)) throw new Error("Invalid revision metadata");
    } catch { return; }
    const changed = {};
    for (const name of due) {
      const state = this.domains[name], revision = revisions[name];
      if (state.observed !== null && revision < state.observed) { state.checked = null; continue; }
      state.observed = revision;
      if (revision === state.revision) { state.checked = started; continue; }
      state.checked = null;
      if (typeof state.refresh !== "function") continue;
      try {
        await state.refresh(revision);
        changed[name] = revision;
      } catch { /* A failed installer cannot renew freshness. */ }
    }
    const names = Object.keys(changed);
    if (!names.length) return;
    let confirmed;
    try {
      confirmed = await this.read(names);
      if (!validMetadata(confirmed, names)) throw new Error("Invalid revision confirmation");
    } catch { return; }
    for (const name of names) {
      this.domains[name].observed = Math.max(this.domains[name].observed || 0, confirmed[name]);
      if (confirmed[name] === changed[name]) {
        this.domains[name].revision = changed[name];
        this.domains[name].checked = started;
      }
    }
  }

  requireFreshSecurity() {
    if (!this.settings.enabled || [...SECURITY_DOMAINS].every(name => this.domains[name].checked !== null
      && this.clock() - this.domains[name].checked <= this.settings.securityTtl)) return null;
    return Response.json({ error: { code: "config_security_stale", message: "Security configuration freshness could not be verified" } },
      { status: 503, headers: { "cache-control": "no-store" } });
  }

  status() {
    const now = this.clock();
    return { enabled: this.settings.enabled, domains: Object.fromEntries(Object.entries(this.domains).map(([name, state]) => [name, {
      revision: state.revision, age_seconds: state.checked === null ? null : Math.max(0, now - state.checked),
      stale: state.checked === null || now - state.checked > (state.security ? this.settings.securityTtl : this.settings.ttl),
      security: state.security, next_poll_seconds: Math.max(0, state.due - now),
    }])) };
  }
}
