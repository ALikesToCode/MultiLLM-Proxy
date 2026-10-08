/** Fixed private operations for immutable, principal-scoped prompt versions. */
const SLUG = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const CONTROL = /[\x00-\x1f\x7f]/;
const PLACEHOLDER = /{{([A-Za-z_][A-Za-z0-9_]{0,63})}}/g;
const MAX_BYTES = 65536;
const MAX_VERSIONS = 100;
const PAGE_SIZE = 2;
const RETENTION_SECONDS = 30 * 86400;
const encoder = new TextEncoder();
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const fields = (value, names) => object(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
const matched = (pattern, value) => typeof value === "string" && !CONTROL.test(value) && pattern.test(value);
const version = value => Number.isSafeInteger(value) && value >= 1 && value <= 2147483647;
const cursor = value => value === null || (fields(value, ["slug", "version"]) && matched(SLUG, value.slug) && version(value.version));
const reply = (value, status = 200) => Response.json(value.error
  ? { version: 1, error: { code: value.error, message: "Prompt template storage operation failed" } }
  : { version: 1, ...value }, { status, headers: { "cache-control": "no-store" } });

export const promptTemplatesEnabled = env => ["1", "true", "yes", "on"].includes(String(env.PROMPT_TEMPLATES_ENABLED ?? "false").trim().toLowerCase());

async function validTemplate(value) {
  if (!fields(value, ["slug", "version", "content", "variables", "content_hash"])
    || !matched(SLUG, value.slug) || !version(value.version) || typeof value.content !== "string"
    || !value.content.isWellFormed() || encoder.encode(value.content).length < 1 || encoder.encode(value.content).length > MAX_BYTES
    || !Array.isArray(value.variables) || value.variables.length > 32 || !value.variables.every(name => matched(NAME, name))
    || new Set(value.variables).size !== value.variables.length) return false;
  const remainder = value.content.replace(PLACEHOLDER, "");
  if (["{{", "}}", "{%", "%}", "{#", "#}"].some(marker => remainder.includes(marker))) return false;
  const declared = new Set(value.variables);
  const found = new Set([...value.content.matchAll(PLACEHOLDER)].map(match => match[1]));
  if (declared.size !== found.size || [...found].some(name => !declared.has(name))) return false;
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value.content))))
    .map(byte => byte.toString(16).padStart(2, "0")).join("");
  return value.content_hash === hash;
}

const record = row => ({ slug: row.slug, version: row.version, content: row.content,
  variables: JSON.parse(row.variables), content_hash: row.content_hash });

async function create(db, body) {
  if (!fields(body, ["version", "operation", "principal", "template", "created_at"])
    || typeof body.created_at !== "number" || !Number.isFinite(body.created_at) || body.created_at < 0
    || body.created_at > Date.now() / 1000 + 300 || !await validTemplate(body.template)) return null;
  const value = body.template;
  // Uniqueness and the owner limit are enforced in the insert, including concurrent requests.
  const result = await db.prepare(`INSERT OR IGNORE INTO prompt_templates
    (principal, slug, version, content_hash, content, variables, created_at)
    SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 WHERE (SELECT COUNT(*) FROM prompt_templates WHERE principal = ?1) < ${MAX_VERSIONS}`)
    .bind(body.principal, value.slug, value.version, value.content_hash, value.content, JSON.stringify(value.variables), body.created_at).run();
  if (result.meta.changes === 1) return reply({ stored: true });
  const existing = await db.prepare("SELECT 1 FROM prompt_templates WHERE principal = ? AND slug = ? AND version = ?")
    .bind(body.principal, value.slug, value.version).first();
  return reply({ error: existing ? "version_conflict" : "limit_reached" }, 409);
}

async function get(db, body) {
  if (!fields(body, ["version", "operation", "principal", "slug", "template_version"])
    || !matched(SLUG, body.slug) || !version(body.template_version)) return null;
  const row = await db.prepare("SELECT slug, version, content_hash, content, variables FROM prompt_templates WHERE principal = ? AND slug = ? AND version = ? AND created_at > ?")
    .bind(body.principal, body.slug, body.template_version, Date.now() / 1000 - RETENTION_SECONDS).first();
  if (row && !await validTemplate(record(row))) throw new Error("Invalid stored template");
  return reply({ template: row ? record(row) : null });
}

async function list(db, body) {
  if (!fields(body, ["version", "operation", "principal", "after"]) || !cursor(body.after)) return null;
  const after = body.after ?? { slug: "", version: 0 };
  const { results } = await db.prepare(`SELECT slug, version, content_hash, content, variables FROM prompt_templates
    WHERE principal = ? AND created_at > ? AND (slug > ? OR (slug = ? AND version > ?)) ORDER BY slug, version LIMIT ${PAGE_SIZE + 1}`)
    .bind(body.principal, Date.now() / 1000 - RETENTION_SECONDS, after.slug, after.slug, after.version).all();
  const templates = results.slice(0, PAGE_SIZE).map(record);
  for (const template of templates) if (!await validTemplate(template)) throw new Error("Invalid stored template");
  const last = templates.at(-1);
  return reply({ templates, next: results.length > PAGE_SIZE ? { slug: last.slug, version: last.version } : null });
}

export async function handlePromptTemplates(db, body) {
  if (body.version !== 1 || typeof body.principal !== "string" || !body.principal.isWellFormed()
    || body.principal.length < 1 || body.principal.length > 128 || CONTROL.test(body.principal)) return null;
  try {
    switch (body.operation) {
      case "create": return await create(db, body);
      case "get": return await get(db, body);
      case "list": return await list(db, body);
      default: return null;
    }
  } catch {
    // Driver exceptions may include bound content; only a fixed diagnostic reaches the dispatcher.
    throw new Error("Prompt template storage unavailable; check migration 0014");
  }
}
