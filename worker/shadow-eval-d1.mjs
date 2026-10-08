/** Bounded private storage; replay dispatch remains in the running Container. */
import SQL from "./shadow-eval-sql.json" with { type: "json" };
import { boundedBody } from "./control-users-d1.mjs";
import { scanPayload } from "./secret-scan.mjs";
import { validatePolicy } from "./intelligence-d1.mjs";
import { logFailure } from "./log.mjs";

const TASKS = ["coding", "extraction", "writing", "reasoning", "chat"];
const MODEL = /^[a-z][a-z0-9-]{0,31}:[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,223}$/;
const ID = /^[0-9a-f]{32}$/;
const bytes = value => new TextEncoder().encode(JSON.stringify(value)).length;
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const finite = value => typeof value === "number" && Number.isFinite(value) && value >= 0;
const model = value => typeof value === "string" && MODEL.test(value);
const identifier = value => typeof value === "string" && ID.test(value);
const fields = (value, names) => object(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
const cleanUsage = value => object(value) && Object.entries(value).every(([name, amount]) =>
  ["prompt_tokens", "completion_tokens", "total_tokens"].includes(name) && Number.isSafeInteger(amount) && amount >= 0 && amount <= 2**31 - 1);
const safe = value => { const report = scanPayload(value); return !report.high && !report.truncated; };

export function validConfig(value) {
  return fields(value, ["enabled", "candidate_models", "judge_model", "max_replays_per_run", "daily_cap"])
    && typeof value.enabled === "boolean" && model(value.judge_model)
    && Number.isSafeInteger(value.max_replays_per_run) && value.max_replays_per_run >= 1 && value.max_replays_per_run <= 20
    && Number.isSafeInteger(value.daily_cap) && value.daily_cap >= 1 && value.daily_cap <= 500
    && fields(value.candidate_models, TASKS) && Object.values(value.candidate_models).every(models =>
      Array.isArray(models) && models.length <= 8 && new Set(models).size === models.length
      && models.every(value => model(value) && !/^(free|roleplay|knowledge):/.test(value)));
}

export function validSample(value, now) {
  return object(value) && fields(Object.fromEntries(Object.entries(value).filter(([name]) => name !== "production_finish_reason")), ["id", "created_at", "key_id", "route", "task_type", "request", "production_model", "production_answer", "latency_ms", "usage"])
    && identifier(value.id) && finite(value.created_at) && value.created_at > now - 604800 && value.created_at <= now + 60
    && typeof value.key_id === "string" && value.key_id.length > 0 && value.key_id.length <= 128
    && model(value.route) && /^(auto|cascade):/.test(value.route) && TASKS.includes(value.task_type)
    && object(value.request) && Array.isArray(value.request.messages)
    && Object.keys(value.request).every(name => ["messages", "tools", "tool_choice", "response_format", "max_tokens", "max_completion_tokens"].includes(name))
    && ["max_tokens", "max_completion_tokens"].every(name => !Object.hasOwn(value.request, name)
      || (Number.isSafeInteger(value.request[name]) && value.request[name] > 0))
    && (!Object.hasOwn(value, "production_finish_reason") || ["stop", "length", "tool_calls", "function_call", "content_filter"].includes(value.production_finish_reason))
    && bytes(value.request) <= 65536 && object(value.production_answer)
    && Object.keys(value.production_answer).every(name => ["content", "tool_calls"].includes(name))
    && bytes(value.production_answer) <= 32768 && model(value.production_model)
    && finite(value.latency_ms) && value.latency_ms <= 86400000 && cleanUsage(value.usage)
    && safe(value.request) && safe(value.production_answer);
}

function validNoiseFloor(value) {
  const outcomes = [null, "win", "loss", "tie"];
  return fields(value, ["version", "run_id", "seed", "bootstrap_draws", "completed_arms", "candidate_first", "pairs", "repeat"])
    && value.version === 1 && identifier(value.run_id)
    && Number.isSafeInteger(value.seed) && value.seed >= 0 && value.seed < 2**32
    && Number.isSafeInteger(value.bootstrap_draws) && value.bootstrap_draws >= 1 && value.bootstrap_draws <= 5000
    && Number.isSafeInteger(value.completed_arms) && value.completed_arms >= 0 && value.completed_arms <= 3
    && Array.isArray(value.candidate_first) && value.candidate_first.length === 3
    && value.candidate_first.every(value => typeof value === "boolean")
    && fields(value.pairs, ["ab", "ac", "bc"]) && Object.values(value.pairs).every(value => outcomes.includes(value))
    && fields(value.repeat, ["model", "latency_ms", "usage", "cost", "tool_validity"])
    && model(value.repeat.model) && finite(value.repeat.latency_ms) && cleanUsage(value.repeat.usage)
    && (value.repeat.cost === null || finite(value.repeat.cost))
    && (value.repeat.tool_validity === null || (fields(value.repeat.tool_validity, ["checked", "valid", "invalid"])
      && Object.values(value.repeat.tool_validity).every(value => Number.isSafeInteger(value) && value >= 0 && value <= 128)));
}

export function validResult(value, noiseFloorEnabled = false) {
  const names = ["sample_id", "task_type", "candidate_model", "candidate_route", "production_model", "outcome",
    "judge_model", "latencies", "usage", "costs", "tool_validity"];
  const threeArm = object(value) && Object.hasOwn(value, "noise_floor");
  if (threeArm) {
    if (noiseFloorEnabled !== true || !validNoiseFloor(value.noise_floor)) return false;
    names.push("noise_floor");
  }
  const maxJudges = threeArm ? 6 : 2;
  return object(value) && fields(Object.fromEntries(Object.entries(value).filter(([name]) => name !== "candidate_truncated")), names)
    && (!Object.hasOwn(value, "candidate_truncated") || typeof value.candidate_truncated === "boolean") && identifier(value.sample_id) && TASKS.includes(value.task_type)
    && [value.candidate_model, value.candidate_route, value.production_model, value.judge_model].every(model)
    && ["win", "loss", "tie", "failed", "same_model", "candidate_truncated"].includes(value.outcome)
    && fields(value.latencies, ["production", "candidate", "judges"])
    && finite(value.latencies.production) && finite(value.latencies.candidate)
    && Array.isArray(value.latencies.judges) && value.latencies.judges.length <= maxJudges && value.latencies.judges.every(finite)
    && fields(value.usage, ["production", "candidate", "judges"])
    && cleanUsage(value.usage.production) && cleanUsage(value.usage.candidate)
    && Array.isArray(value.usage.judges) && value.usage.judges.length <= maxJudges && value.usage.judges.every(cleanUsage)
    && fields(value.costs, ["production", "candidate", "judges"])
    && [value.costs.production, value.costs.candidate].every(value => value === null || finite(value))
    && Array.isArray(value.costs.judges) && value.costs.judges.length <= maxJudges
    && value.costs.judges.every(value => value === null || finite(value))
    && (value.tool_validity === null || (fields(value.tool_validity, ["production", "candidate"])
      && Object.values(value.tool_validity).every(value => fields(value, ["checked", "valid", "invalid"])
        && Object.values(value).every(value => Number.isSafeInteger(value) && value >= 0 && value <= 128))))
    && (!threeArm || (value.latencies.judges.length === value.usage.judges.length
      && value.usage.judges.length === value.costs.judges.length
      && (!["win", "loss", "tie"].includes(value.outcome)
        || (value.noise_floor.completed_arms === 3 && value.usage.judges.length === 6
          && Object.values(value.noise_floor.pairs).every(value => value !== null)
          && value.noise_floor.repeat.model === value.production_model && value.candidate_model !== value.production_model
          && !value.candidate_truncated
          && value.outcome === (value.noise_floor.pairs.ac === value.noise_floor.pairs.bc ? value.noise_floor.pairs.ac : "tie")))))
    && bytes(value) <= 4096;
}

const FIELDS = {
  cleanup: [], config_get: [], config_seed: ["document"], config_save: ["document", "expected"],
  put: ["id", "created_at", "document"], sample: ["id"], samples: [], pending: ["task", "candidate"],
  lease: ["run_id", "until"], release: ["run_id"], claim: ["sample_id", "candidate", "config", "run_id", "id"],
  claim_three_arm: ["sample_id", "candidate", "config", "run_id", "id"],
  finish: ["id", "document"], results: ["after"], purge: [], apply: ["expected", "document", "id"],
};
const canonical = value => JSON.stringify(object(value)
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, JSON.parse(canonical(value[key]))]))
  : Array.isArray(value) ? value.map(item => JSON.parse(canonical(item))) : value);

function validBody(body, now, noiseFloorEnabled = false) {
  if (body.operation === "claim_three_arm" && !noiseFloorEnabled) return false;
  const names = FIELDS[body.operation];
  if (!names || !fields(body, ["version", "operation", ...names]) || body.version !== 1) return false;
  for (const name of ["id", "sample_id", "run_id"]) if (Object.hasOwn(body, name) && !identifier(body[name])) return false;
  if (Object.hasOwn(body, "candidate") && !model(body.candidate)) return false;
  if (Object.hasOwn(body, "task") && !TASKS.includes(body.task)) return false;
  if (body.operation === "results" && body.after !== "" && !identifier(body.after)) return false;
  if (body.operation === "lease" && (!finite(body.until) || body.until < now || body.until > now + 301)) return false;
  for (const name of ["document", "expected", "config"]) {
    if (!Object.hasOwn(body, name)) continue;
    if (typeof body[name] !== "string" || new TextEncoder().encode(body[name]).length > 131072) return false;
    try {
      const value = JSON.parse(body[name]);
      if (["config_seed", "config_save", "claim", "claim_three_arm"].includes(body.operation) && !validConfig(value)) return false;
      if (body.operation === "put" && (!validSample(value, now) || value.id !== body.id || value.created_at !== body.created_at)) return false;
      if (body.operation === "finish" && !validResult(value, noiseFloorEnabled)) return false;
      if (body.operation === "apply") validatePolicy(value);
    } catch { return false; }
  }
  return true;
}

const reply = (result, status = 200) => Response.json(status === 200 ? { version: 1, result }
  : { version: 1, error: { code: result, message: "Shadow evaluation storage operation failed" } },
  { status, headers: { "cache-control": "no-store" } });

export async function handleShadowEvalRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal" || url.pathname !== "/v1/shadow-eval"
    || url.search || url.hash || url.username || url.password) return reply("not_found", 404);
  let body;
  const now = Date.now() / 1000;
  try {
    if (request.headers.get("content-type")?.split(";", 1)[0].trim() !== "application/json") throw new Error();
    body = JSON.parse(await boundedBody(request, 262144));
    const noiseFloorEnabled = String(env.SHADOW_EVAL_NOISE_FLOOR_ENABLED || "").toLowerCase() === "true";
    if (!object(body) || !validBody(body, now, noiseFloorEnabled)) throw new Error();
  } catch { return reply("invalid_request", 400); }
  const db = env.INTELLIGENCE_DB;
  if (!db) return reply("storage_unavailable", 503);
  try {
    let values = { now, cutoff: now - 604800, result_cutoff: now - 90 * 86400, day: Math.floor(now / 86400), ...body };
    if (body.operation === "apply") {
      const stored = await db.prepare("SELECT document FROM intelligence_policy WHERE id = 1").first();
      if (!stored || canonical(validatePolicy(JSON.parse(stored.document))) !== canonical(validatePolicy(JSON.parse(body.expected)))) return reply(false);
      values.expected = stored.document;
    }
    const statements = SQL[body.operation].map(sql => {
      // Bind only fixed named placeholders; never execute caller-provided SQL.
      const names = [...new Set([...sql.matchAll(/:([a-z_]+)/g)].map(match => match[1]))];
      const numbered = sql.replace(/:([a-z_]+)/g, (_, name) => `?${names.indexOf(name) + 1}`);
      return names.length ? db.prepare(numbered).bind(...names.map(name => values[name])) : db.prepare(numbered);
    });
    const results = await db.batch(statements);
    let result;
    if (["config_get", "sample", "pending"].includes(body.operation)) {
      result = results[0].results.length ? JSON.parse(results[0].results[0].document) : null;
    } else if (["samples", "results"].includes(body.operation)) result = results[0].results;
    else result = results[["claim", "claim_three_arm", "apply"].includes(body.operation) ? 1 : 0].meta.changes === 1;
    return reply(result);
  } catch (error) {
    logFailure("shadow_eval_storage_failed", error);
    return reply("storage_unavailable", 503);
  }
}
