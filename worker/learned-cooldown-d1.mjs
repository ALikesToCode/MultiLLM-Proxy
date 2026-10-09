/** Private storage for passive cooldown evidence; no provider dispatch or retries. */
export const TTL_SECONDS = 7 * 24 * 3600;
export const MAX_ENTRIES = 1024;
export const MAX_RPC_BYTES = 4096;
const HASH = /^[0-9a-f]{64}$/;
const FIELDS = ["credential_digest", "lower_seconds", "upper_seconds", "trial_seconds", "samples", "consistent",
  "steps", "confident", "last_kind", "last_throttle", "last_observed", "floor_until", "created_at", "expires_at", "revision"];
const COLUMNS = FIELDS.join(", ");
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const exact = (value, fields) => object(value) && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
const number = value => typeof value === "number" && Number.isFinite(value) && value >= 0;
const integer = (value, low, high) => Number.isSafeInteger(value) && value >= low && value <= high;
const digest = value => typeof value === "string" && HASH.test(value);
const warned = new Set();
function warnOnce(name) {
  if (warned.has(name)) return;
  warned.add(name);
  console.warn(`${name}; learned cooldown uses existing behaviour`);
}
const reply = (value, status = 200) => Response.json({ version: 1, ...value }, { status, headers: { "cache-control": "no-store" } });
const failure = (code, status) => reply({ error: { code, message: "Learned cooldown state is unavailable." } }, status);

export function learnedCooldownEnabled(env = {}) {
  const mode = (env.LEARNED_COOLDOWN_MODE || "off").trim().toLowerCase() || "off";
  if (["shadow", "apply"].includes(mode)) return true;
  if (mode !== "off") warnOnce("Invalid LEARNED_COOLDOWN_MODE");
  return false;
}

export function validLearnedState(value, credential, now) {
  if (!exact(value, FIELDS) || !digest(credential) || value.credential_digest !== credential
    || !integer(value.lower_seconds, 1, 3600) || !integer(value.upper_seconds, value.lower_seconds, 3600)
    || !integer(value.trial_seconds, 1, 3600) || !integer(value.samples, 0, 2147483647)
    || !integer(value.consistent, 0, 3) || !integer(value.steps, 0, 12) || !integer(value.revision, 1, 2147483647)
    || typeof value.confident !== "boolean" || !["none", "failure", "success"].includes(value.last_kind)
    || !["last_observed", "floor_until", "created_at", "expires_at"].every(key => number(value[key]))) return false;
  return (value.last_throttle === null || number(value.last_throttle) && value.last_throttle >= value.created_at
    && value.last_throttle <= value.last_observed) && value.created_at <= value.last_observed
    && value.last_observed <= now && now < value.expires_at && value.expires_at === value.created_at + TTL_SECONDS;
}

const INSERT = `INSERT INTO learned_cooldown (bucket_digest, ${COLUMNS})
  SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
  WHERE ?17=0 AND (SELECT COUNT(*) FROM learned_cooldown) < ${MAX_ENTRIES}
  ON CONFLICT(bucket_digest) DO NOTHING`;
const UPDATE = `UPDATE learned_cooldown SET ${FIELDS.map((field, index) => `${field}=?${index + 2}`).join(", ")}
  WHERE bucket_digest=?1 AND credential_digest=?2 AND revision=?17 AND expires_at>?18
    AND created_at=?14 AND expires_at=?15 AND last_observed<=?12
    AND samples<=?6 AND steps<=?8`;

async function read(db, body) {
  const entry = await db.prepare(`SELECT ${COLUMNS} FROM learned_cooldown
    WHERE bucket_digest=? AND credential_digest=? AND expires_at>?`)
    .bind(body.bucket_digest, body.credential_digest, body.now).first();
  if (!entry) return reply({ entry: null });
  if (![0, 1].includes(entry.confident)) throw new Error("invalid_storage_entry");
  entry.confident = entry.confident === 1;
  if (!validLearnedState(entry, body.credential_digest, body.now)) throw new Error("invalid_storage_entry");
  return reply({ entry });
}

async function write(db, body) {
  const args = [body.bucket_digest, ...FIELDS.map(field => field === "confident" ? Number(body.entry[field]) : body.entry[field]), body.expected_revision];
  // The transactional batch serializes both capacity checks and stale revisions.
  const results = await db.batch([
    db.prepare("DELETE FROM learned_cooldown WHERE expires_at<=?").bind(body.now),
    db.prepare(body.expected_revision === 0 ? INSERT : UPDATE)
      .bind(...args, ...(body.expected_revision === 0 ? [] : [body.now])),
  ]);
  return reply({ stored: results[1].meta.changes === 1 });
}

export async function handleLearnedCooldown(db, body, env = {}) {
  if (!learnedCooldownEnabled(env)) return failure("not_found", 404);
  const base = ["version", "operation", "bucket_digest", "credential_digest", "now"];
  if (!object(body) || body.version !== 1 || !["get", "put"].includes(body.operation)
    || !digest(body.bucket_digest) || !digest(body.credential_digest) || !number(body.now)
    || body.now > 8640000000000 || !exact(body, body.operation === "get" ? base : [...base, "expected_revision", "entry"])) {
    return failure("invalid_request", 400);
  }
  if (body.operation === "put" && (!integer(body.expected_revision, 0, 2147483646)
    || !validLearnedState(body.entry, body.credential_digest, body.now) || body.entry.revision !== body.expected_revision + 1)) {
    return failure("invalid_request", 400);
  }
  try {
    if (!db) throw new Error("storage_unavailable");
    return await (body.operation === "get" ? read(db, body) : write(db, body));
  } catch {
    warnOnce("Learned cooldown storage unavailable");
    return failure("learned_cooldown_storage_unavailable", 503);
  }
}
