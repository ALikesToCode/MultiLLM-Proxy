/** Content-free durable alerts; private state and scheduled delivery are fixed collaborators. */
const MAX_BYTES = 8192;
const MAX_RULES = 20;
const MAX_EVENTS = 2000;
const RETENTION_SECONDS = 7 * 86400;
const DEDUPE_SECONDS = 900;
const TIMEOUT_MS = 3000;
const encoder = new TextEncoder();
const warned = new Set();
const ID = /^[0-9a-f]{64}$/;
const WINDOW = /^(?:current|[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?)$/;
const KINDS = new Set(["spend", "unknown_price", "provider_circuit", "pool_exhaustion", "provider_health"]);
const PROVIDERS = new Set(["openai", "anthropic", "cerebras", "googleai", "xai", "groq", "together", "azure",
  "scaleway", "hyperbolic", "sambanova", "openrouter", "opencode", "mimo", "nanogpt", "navyai", "linkapi",
  "aihubmix", "codex-easy", "kimi-code", "cline-pass", "palm", "nineteen", "chutes", "gemini", "gemma"]);
const basisFor = kind => kind === "spend" ? "gateway_cost_estimate" : kind === "unknown_price" ? "unknown_price_coverage" : "observed_health";
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const fields = (value, names) => object(value) && Object.keys(value).length === names.length && names.every(key => Object.hasOwn(value, key));
const number = value => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1e12;
const revision = value => Number.isSafeInteger(value) && value >= 0 && value < Number.MAX_SAFE_INTEGER;
const matched = (pattern, value) => typeof value === "string" && pattern.test(value);
const reply = (value, status = 200) => Response.json({ version: 1, ...value }, { status, headers: { "cache-control": "no-store" } });
const error = (code, status = 400) => reply({ error: { code } }, status);
function warn(name) {
  if (!warned.has(name)) { warned.add(name); console.warn(`Invalid gateway alert setting (${name})`); }
}
function bounded(value, limit = MAX_BYTES) {
  const text = JSON.stringify(value);
  if (typeof text !== "string" || encoder.encode(text).length > limit) throw Error("Invalid alert size");
  return text;
}
async function digest(value) {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))))
    .map(byte => byte.toString(16).padStart(2, "0")).join("");
}
function numericIdentity(value) {
  if (typeof value !== "number") return value;
  const buffer = new ArrayBuffer(8);
  new DataView(buffer).setFloat64(0, value);
  return "n:" + Array.from(new Uint8Array(buffer)).map(byte => byte.toString(16).padStart(2, "0")).join("");
}
function canonical(rule) {
  return JSON.stringify(Object.fromEntries(Object.keys(rule).sort().map(key => [key,
    Array.isArray(rule[key]) ? rule[key].map(numericIdentity) : numericIdentity(rule[key])])));
}
function origin(value) {
  if (typeof value !== "string" || value.length > 2048 || /[^\x21-\x7e]|\\/.test(value)) throw Error("Invalid destination");
  const url = new URL(value);
  const host = url.hostname;
  if (url.protocol !== "https:" || url.username || url.password || url.port || value.includes("?") || value.includes("#")
      || !/^[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)+$/.test(host)
      || /\.(?:localhost|local|internal|invalid|test|home|lan|[0-9]+)$/.test(host) || host.startsWith("metadata.")) throw Error("Invalid destination");
  return url.origin;
}
export function alertSettings(env) {
  const flag = String(env.GATEWAY_ALERTS_ENABLED ?? "").trim().toLowerCase();
  let enabled = ["1", "true", "yes", "on"].includes(flag);
  if (!["", "0", "1", "false", "true", "no", "yes", "off", "on"].includes(flag)) warn("GATEWAY_ALERTS_ENABLED");
  let allowlist = new Set();
  try {
    const list = JSON.parse(String(env.GATEWAY_ALERT_WEBHOOK_ALLOWLIST ?? "").trim() || "[]");
    if (!Array.isArray(list) || list.length > 20) throw Error("Invalid allowlist");
    for (const value of list) {
      const item = origin(value);
      if (![item, item + "/", item + ":443", item + ":443/"].includes(value)) throw Error("Invalid origin");
      allowlist.add(item);
    }
  } catch { enabled = false; allowlist = new Set(); warn("GATEWAY_ALERT_WEBHOOK_ALLOWLIST"); }
  return { enabled, allowlist };
}
export function validateDestination(value, allowlist) {
  if (!allowlist.has(origin(value))) throw Error("Destination not allowed");
  return value;
}
export async function normalizeAlertRules(values, providers = PROVIDERS) {
  if (!Array.isArray(values) || values.length > MAX_RULES) throw Error("Invalid rules");
  const result = [], seen = new Set();
  for (const input of values) {
    if (!object(input) || !KINDS.has(input.kind)) throw Error("Invalid kind");
    const { id, ...value } = input;
    const kind = value.kind;
    const allowed = kind === "spend" ? ["kind", "period", "budget_usd", "thresholds"]
      : kind === "unknown_price" ? ["kind", "period", "threshold_percent"]
        : kind === "provider_health" ? ["kind", "provider", "failures"] : ["kind", "provider"];
    if (Object.keys(value).some(key => !allowed.includes(key))) throw Error("Invalid rule fields");
    const rule = { kind };
    if (["spend", "unknown_price"].includes(kind)) {
      if (!["day", "month"].includes(value.period)) throw Error("Invalid period");
      rule.period = value.period;
    } else {
      if (!providers.has(value.provider)) throw Error("Invalid provider");
      rule.provider = value.provider;
    }
    if (kind === "spend") {
      const thresholds = value.thresholds ?? [85, 100];
      if (!number(value.budget_usd) || !value.budget_usd || !Array.isArray(thresholds) || thresholds.length < 1 || thresholds.length > 4
          || thresholds.some(t => !number(t) || t <= 0 || t > 100) || new Set(thresholds).size !== thresholds.length) throw Error("Invalid spend rule");
      rule.budget_usd = value.budget_usd;
      rule.thresholds = [...thresholds].sort((a, b) => a - b);
    } else if (kind === "unknown_price") {
      rule.threshold_percent = value.threshold_percent ?? 0;
      if (!number(rule.threshold_percent) || rule.threshold_percent > 100) throw Error("Invalid coverage rule");
    } else if (kind === "provider_health") {
      rule.failures = value.failures ?? 3;
      if (!Number.isSafeInteger(rule.failures) || rule.failures < 1 || rule.failures > 100) throw Error("Invalid health rule");
    }
    const identifier = await digest(canonical(rule));
    if (seen.has(identifier) || id !== undefined && id !== identifier) throw Error("Invalid rule identity");
    seen.add(identifier);
    result.push({ ...rule, id: identifier });
  }
  bounded(result);
  return result;
}
function validPayload(value, providers) {
  return fields(value, ["event", "rule_id", "revision", "occurred_at", "basis", "value", "threshold", "window", "provider"])
    && KINDS.has(value.event) && matched(ID, value.rule_id) && revision(value.revision) && number(value.occurred_at)
    && number(value.value) && number(value.threshold) && value.basis === basisFor(value.event) && matched(WINDOW, value.window)
    && (value.provider === null || providers.has(value.provider));
}
async function readConfig(db, providers) {
  const row = await db.prepare("SELECT revision, configuration FROM gateway_alert_rules WHERE id = 1").first();
  if (!row) return { revision: 0, rules: [], destination: null };
  const value = JSON.parse(row.configuration);
  if (!revision(row.revision) || !fields(value, ["destination", "rules"])) throw Error("Invalid stored configuration");
  origin(value.destination);
  const rules = await normalizeAlertRules(value.rules, providers);
  return { revision: row.revision, rules, destination: value.destination };
}
async function status(db, config, now, providers) {
  const { results } = await db.prepare(`SELECT event_id, state, attempts, last_attempt_at, error_code, payload
    FROM gateway_alert_events WHERE created_at > ? ORDER BY created_at DESC, event_id LIMIT 100`).bind(now - RETENTION_SECONDS).all();
  const events = results.map(row => {
    const payload = JSON.parse(row.payload);
    if (!validPayload(payload, providers) || !matched(ID, row.event_id)
        || !["pending", "delivered", "failed"].includes(row.state)
        || !Number.isSafeInteger(row.attempts) || row.attempts < 0 || row.attempts > 3
        || row.last_attempt_at !== null && !number(row.last_attempt_at)
        || ![null, "delivery_failed", "rule_replaced", "invalid_payload", "attempts_exhausted"].includes(row.error_code)) {
      throw Error("Invalid stored event");
    }
    return { id: row.event_id, state: row.state, attempts: row.attempts, last_attempt_at: row.last_attempt_at,
      error_code: row.error_code, payload };
  });
  const result = { revision: config.revision, rules: config.rules, webhook_configured: config.destination !== null, events };
  bounded(result, 65536);
  return reply(result);
}
async function configure(db, body, settings, now, providers) {
  if (!fields(body, ["version", "operation", "revision", "configuration"]) || !revision(body.revision)
      || body.revision >= Number.MAX_SAFE_INTEGER - 1 || !fields(body.configuration, ["destination", "rules"])) return error("invalid_gateway_alert");
  let configuration;
  try {
    configuration = { destination: validateDestination(body.configuration.destination, settings.allowlist),
      rules: await normalizeAlertRules(body.configuration.rules, providers) };
    bounded(configuration);
  } catch { return error("invalid_gateway_alert"); }
  const next = body.revision + 1;
  const results = await db.batch([
    db.prepare(`INSERT INTO gateway_alert_rules(id, revision, configuration, updated_at)
      SELECT 1, ?1, ?2, ?3 WHERE ?4 = 0 OR EXISTS (SELECT 1 FROM gateway_alert_rules WHERE id = 1 AND revision = ?4)
      ON CONFLICT(id) DO UPDATE SET revision = excluded.revision, configuration = excluded.configuration, updated_at = excluded.updated_at
      WHERE gateway_alert_rules.revision = ?4`).bind(next, bounded(configuration), now, body.revision),
    db.prepare(`UPDATE gateway_alert_events SET state = 'failed', error_code = 'rule_replaced', claim_token = NULL, lease_until = 0
      WHERE state = 'pending' AND revision <> ?1 AND EXISTS (SELECT 1 FROM gateway_alert_rules WHERE id = 1 AND revision = ?1)`).bind(next),
  ]);
  if (results[0].meta.changes !== 1) return error("gateway_alert_revision_conflict", 409);
  return status(db, { revision: next, ...configuration }, now, providers);
}
function validObservation(row, rule) {
  return fields(row, ["rule_id", "value", "basis", "window"]) && matched(ID, row.rule_id) && rule
    && number(row.value) && row.basis === basisFor(rule.kind) && matched(WINDOW, row.window)
    && (rule.period === "day" ? /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(row.window)
      : rule.period === "month" ? /^[0-9]{4}-[0-9]{2}$/.test(row.window) : row.window === "current")
    && (rule.kind !== "unknown_price" || row.value <= 100)
    && (!["provider_circuit", "pool_exhaustion"].includes(rule.kind) || [0, 1].includes(row.value));
}
async function enqueue(db, config, observations, now) {
  const byId = new Map(config.rules.map(rule => [rule.id, rule]));
  if (!Array.isArray(observations) || observations.length > MAX_RULES || new Set(observations.map(row => row?.rule_id)).size !== observations.length
      || observations.some(row => !validObservation(row, byId.get(row?.rule_id)))) return error("invalid_gateway_alert");
  const statements = [];
  for (const row of observations) {
    const rule = byId.get(row.rule_id);
    const thresholds = rule.kind === "spend" ? rule.thresholds : [rule.kind === "unknown_price" ? rule.threshold_percent : rule.failures ?? 1];
    const measured = rule.kind === "spend" ? row.value / rule.budget_usd * 100 : row.value;
    for (const threshold of thresholds) {
      if (measured < threshold || rule.kind === "unknown_price" && row.value === 0) continue;
      const dedupe = await digest(canonical({ kind: rule.kind, rule_id: rule.id, revision: config.revision, threshold, window: row.window }));
      const payload = { event: rule.kind, rule_id: rule.id, revision: config.revision, occurred_at: now,
        basis: row.basis, value: row.value, threshold, window: row.window, provider: rule.provider ?? null };
      const eventId = await digest(dedupe + ":" + crypto.randomUUID());
      statements.push(db.prepare(`INSERT INTO gateway_alert_events
        (dedupe_key, event_id, rule_id, revision, payload, created_at, state, next_attempt_at)
        SELECT ?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?6
        WHERE EXISTS (SELECT 1 FROM gateway_alert_rules WHERE id = 1 AND revision = ?4)
          AND ((SELECT COUNT(*) FROM gateway_alert_events) < ${MAX_EVENTS} OR EXISTS (SELECT 1 FROM gateway_alert_events WHERE dedupe_key = ?1))
        ON CONFLICT(dedupe_key) DO UPDATE SET event_id = excluded.event_id, payload = excluded.payload,
          created_at = excluded.created_at, state = 'pending', attempts = 0, attempt_times = '[]', last_attempt_at = NULL,
          next_attempt_at = excluded.next_attempt_at, claim_token = NULL, lease_until = 0, error_code = NULL
        WHERE gateway_alert_events.created_at <= ?7 AND gateway_alert_events.lease_until <= ?6`)
        .bind(dedupe, eventId, rule.id, config.revision, bounded(payload), now, now - DEDUPE_SECONDS));
    }
  }
  if (!statements.length) return reply({ queued: 0 });
  const results = await db.batch(statements);
  return reply({ queued: results.reduce((sum, row) => sum + row.meta.changes, 0) });
}
/** Call only from the authenticated private managed-state dispatcher. */
export async function handleAlertState(env, body, { clock = () => Date.now() / 1000, providers = PROVIDERS } = {}) {
  const settings = alertSettings(env);
  if (!settings.enabled) return error("not_found", 404);
  if (!object(body) || body.version !== 1 || !["get", "configure", "observe"].includes(body.operation)) return error("invalid_gateway_alert");
  try { bounded(body); } catch { return error("gateway_alert_too_large", 413); }
  const db = env.INTELLIGENCE_DB, now = clock();
  if (!db || !number(now)) return error("gateway_alert_storage_unavailable", 503);
  try {
    const config = await readConfig(db, providers);
    if (body.operation === "get") {
      if (!fields(body, ["version", "operation"])) return error("invalid_gateway_alert");
      return await status(db, config, now, providers);
    }
    if (body.operation === "configure") return await configure(db, body, settings, now, providers);
    if (!fields(body, ["version", "operation", "revision", "observations"]) || !revision(body.revision)) return error("invalid_gateway_alert");
    if (body.revision !== config.revision) return error("gateway_alert_revision_conflict", 409);
    return await enqueue(db, config, body.observations, now);
  } catch { return error("gateway_alert_storage_unavailable", 503); }
}
async function prune(db, now) {
  await db.prepare(`DELETE FROM gateway_alert_events WHERE dedupe_key IN (
    SELECT dedupe_key FROM gateway_alert_events WHERE created_at <= ? AND lease_until <= ? LIMIT 100)`)
    .bind(now - RETENTION_SECONDS, now).run();
  await db.prepare(`UPDATE gateway_alert_events SET state = 'failed', error_code = 'attempts_exhausted', claim_token = NULL, lease_until = 0
    WHERE state = 'pending' AND attempts >= 3 AND lease_until <= ?`).bind(now).run();
}
async function claim(db, config, now) {
  const token = crypto.randomUUID();
  const result = await db.prepare(`UPDATE gateway_alert_events SET claim_token = ?1, lease_until = ?2, attempts = attempts + 1,
    last_attempt_at = ?3, attempt_times = json_insert(attempt_times, '$[#]', ?3)
    WHERE dedupe_key IN (SELECT dedupe_key FROM gateway_alert_events WHERE state = 'pending' AND attempts < 3
      AND next_attempt_at <= ?3 AND lease_until <= ?3 AND revision = ?4 AND created_at > ?5 ORDER BY next_attempt_at, created_at LIMIT 10)
      AND EXISTS (SELECT 1 FROM gateway_alert_rules WHERE id = 1 AND revision = ?4)
    RETURNING event_id, payload, attempts, claim_token`).bind(token, now + 45, now, config.revision, now - RETENTION_SECONDS).all();
  return result.results;
}
async function finish(db, row, now, succeeded, code) {
  await db.prepare(`UPDATE gateway_alert_events SET state = ?1, error_code = ?2, next_attempt_at = ?3,
    claim_token = NULL, lease_until = 0 WHERE event_id = ?4 AND claim_token = ?5 AND state = 'pending'`)
    .bind(succeeded ? "delivered" : row.attempts >= 3 || code === "invalid_payload" ? "failed" : "pending",
      succeeded ? null : code, now + 60, row.event_id, row.claim_token).run();
}
async function deliver(transport, destination, payload) {
  const controller = new AbortController();
  let timer;
  try {
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(Error("Delivery timeout")); }, TIMEOUT_MS); });
    const response = await Promise.race([Promise.resolve().then(() => transport(destination, {
      method: "POST", headers: { "content-type": "application/json" }, body: bounded(payload),
      redirect: "error", signal: controller.signal, timeoutMs: TIMEOUT_MS,
    })), timeout]);
    return Number.isInteger(response?.status) && response.status >= 200 && response.status < 300 && !response.redirected;
  } catch { return false; }
  finally { controller.abort(); clearTimeout(timer); }
}
/** The scheduler supplies one reviewed metrics collector and a redirect-rejecting transport. */
export async function runAlertDelivery(env, { collect, transport, clock = () => Date.now() / 1000, providers = PROVIDERS } = {}) {
  const result = { attempted: 0, delivered: 0, failed: 0 };
  const settings = alertSettings(env);
  if (!settings.enabled || settings.allowlist.size === 0 || typeof transport !== "function") return result;
  const db = env.INTELLIGENCE_DB;
  if (!db) return { ...result, error: "gateway_alert_storage_unavailable" };
  try {
    const now = clock();
    if (!number(now)) throw Error("Invalid time");
    const config = await readConfig(db, providers);
    if (!config.destination || !config.rules.length) return result;
    try { validateDestination(config.destination, settings.allowlist); } catch { return result; }
    await prune(db, now);
    if (typeof collect === "function") {
      const observations = await collect(config.rules);
      bounded(observations);
      const queued = await enqueue(db, config, observations, now);
      if (queued.status !== 200) return { ...result, error: "gateway_alert_observation_unavailable" };
    }
    const rows = await claim(db, config, now);
    // Parallel deliveries finish within one timeout window, before the lease expires.
    await Promise.all(rows.map(async row => {
      result.attempted++;
      let payload;
      try {
        bounded(row.payload);
        payload = JSON.parse(row.payload);
        if (!validPayload(payload, providers)) throw Error("Invalid payload");
      } catch {
        result.failed++;
        await finish(db, row, clock(), false, "invalid_payload");
        return;
      }
      const succeeded = await deliver(transport, config.destination, payload);
      if (succeeded) result.delivered++;
      else if (row.attempts === 3) result.failed++;
      await finish(db, row, clock(), succeeded, "delivery_failed");
    }));
    return result;
  } catch { return { ...result, error: "gateway_alert_storage_unavailable" }; }
}
