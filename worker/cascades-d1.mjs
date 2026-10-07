/** Fixed, bounded cascade control-plane operations; no provider dispatch. */
import { boundedBody } from "./control-users-d1.mjs";
import { logFailure } from "./log.mjs";

const NAME = /^cascade:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/;
const CHECKS = ["complete", "json", "tools", "no_refusal", "agreement", "judge"];
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const fields = (value, allowed) => object(value) && Object.keys(value).every(key => allowed.includes(key));
const model = value => typeof value === "string" && MODEL.test(value)
  && value.includes(":") && value.split(":")[1] && !value.startsWith("cascade:")
  && (!value.startsWith("auto:") || /^auto:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value));
const reply = (value, status = 200) => Response.json(value.error
  ? { version: 1, error: { code: value.error, message: "Cascade storage operation failed" } }
  : value, { status, headers: { "cache-control": "no-store" } });

export function validCascade(value) {
  if (!fields(value, ["name", "tiers", "checks", "judge", "agreement", "updated_at"])
    || typeof value.name !== "string" || !NAME.test(value.name)
    || !Array.isArray(value.tiers) || value.tiers.length < 2 || value.tiers.length > 4
    || !value.tiers.every(tier => fields(tier, ["model", "max_output_tokens"]) && model(tier.model)
      && (!Object.hasOwn(tier, "max_output_tokens") || (Number.isInteger(tier.max_output_tokens)
        && tier.max_output_tokens >= 1 && tier.max_output_tokens <= 1048576)))
    || !Array.isArray(value.checks) || value.checks.length > CHECKS.length
    || !value.checks.every(check => CHECKS.includes(check)) || new Set(value.checks).size !== value.checks.length) return false;
  if (Object.hasOwn(value, "judge") && (!fields(value.judge, ["model", "min_score"]) || !model(value.judge.model)
    || (Object.hasOwn(value.judge, "min_score") && (typeof value.judge.min_score !== "number"
      || !Number.isFinite(value.judge.min_score) || value.judge.min_score < 0 || value.judge.min_score > 10)))) return false;
  if (Object.hasOwn(value, "agreement") && (!fields(value.agreement, ["model"])
    || (Object.hasOwn(value.agreement, "model") && !model(value.agreement.model)))) return false;
  return (!value.checks.includes("judge") || Object.hasOwn(value, "judge"))
    && (!Object.hasOwn(value, "updated_at") || (typeof value.updated_at === "string" && /^[0-9T:.+\-Z]{10,40}$/.test(value.updated_at)));
}

export async function handleCascadesRequest(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.origin !== "http://intelligence.internal"
    || url.pathname !== "/v1/cascades" || url.search || url.hash || url.username || url.password) return reply({ error: "not_found" }, 404);
  if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") return reply({ error: "invalid_request" }, 400);
  if (!env.INTELLIGENCE_DB) return reply({ error: "storage_unavailable" }, 503);
  let body;
  try {
    body = JSON.parse(await boundedBody(request, 16384));
    if (!object(body) || body.version !== 1) return reply({ error: "invalid_request" }, 400);
  } catch { return reply({ error: "invalid_request" }, 400); }
  try {
    const db = env.INTELLIGENCE_DB;
    if (body.operation === "list" && Object.keys(body).length === 2) {
      const { results } = await db.prepare("SELECT config FROM cascades ORDER BY name LIMIT 200").all();
      const cascades = results.map(row => JSON.parse(row.config));
      if (!cascades.every(validCascade)) return reply({ error: "storage_unavailable" }, 503);
      return reply({ version: 1, cascades });
    }
    if (body.operation === "put" && Object.keys(body).length === 3 && validCascade(body.cascade)
      && Object.hasOwn(body.cascade, "updated_at")) {
      const cascade = { ...body.cascade, checks: CHECKS.filter(check => body.cascade.checks.includes(check)) };
      if (cascade.judge) cascade.judge = { min_score: 7, ...cascade.judge };
      // Capacity and upsert are one statement, including concurrent creations.
      const result = await db.prepare(`INSERT INTO cascades (name, config, updated_at)
        SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM cascades WHERE name=?) OR (SELECT COUNT(*) FROM cascades) < 200
        ON CONFLICT(name) DO UPDATE SET config=excluded.config, updated_at=excluded.updated_at`)
        .bind(cascade.name, JSON.stringify(cascade), cascade.updated_at, cascade.name).run();
      if (!result.meta.changes) return reply({ error: "cascade_limit_reached" }, 409);
      return reply({ version: 1, stored: true });
    }
    return reply({ error: "invalid_request" }, 400);
  } catch (error) {
    logFailure("cascade_storage_failed", error, { operation: body.operation === "list" ? "list" : "put" });
    return reply({ error: "storage_unavailable" }, 503);
  }
}
