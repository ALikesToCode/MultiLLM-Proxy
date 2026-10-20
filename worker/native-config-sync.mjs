/** Native bootstrap authentication stays in the route; revision authority is strict D1. */
import { RevisionConsumer, revisionSyncSettings } from "./config-revision.mjs";
import { USER_FIELDS, validUser } from "./control-users-d1.mjs";

const consumers = new WeakMap();
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/;

async function loadOverrides(db) {
  const { results } = await db.prepare("SELECT model_id, status FROM control_model_overrides ORDER BY model_id LIMIT 2001").all();
  if (!Array.isArray(results) || results.length > 2000 || results.some(row => !MODEL.test(row.model_id)
    || !row.model_id.includes(":") || !["available", "disabled"].includes(row.status))
    || new Set(results.map(row => row.model_id)).size !== results.length) throw new Error("Invalid model controls");
  return new Map(results.map(row => [row.model_id, row.status]));
}

async function loadAccounts(db) {
  const controls = new Map();
  let after = null;
  while (true) {
    const query = after === null
      ? db.prepare(`SELECT ${USER_FIELDS.join(", ")} FROM control_users ORDER BY username LIMIT ?`).bind(200)
      : db.prepare(`SELECT ${USER_FIELDS.join(", ")} FROM control_users WHERE username > ? ORDER BY username LIMIT ?`).bind(after, 200);
    const { results } = await query.all();
    if (!Array.isArray(results) || results.length > 200) throw new Error("Invalid account controls");
    for (const row of results) {
      if (!USER_FIELDS.every(field => Object.hasOwn(row, field)) || !validUser(row)
        || after !== null && row.username <= after) throw new Error("Invalid account controls");
      after = row.username;
      // Bootstrap admin keys use environment authority, never these stored key hashes.
      controls.set(row.username, Object.freeze({ scopes: row.scopes, allowed_models: row.allowed_models,
        revoked_at: row.revoked_at, expires_at: row.expires_at, allowed_ips: row.allowed_ips }));
    }
    if (results.length < 200) return controls;
  }
}

export function nativeRevisionConsumer(env, options = {}) {
  if (!revisionSyncSettings(env).enabled) return null;
  let entry = consumers.get(env);
  if (!entry) {
    const installed = {};
    const refreshers = {
      async model_overrides() { installed.model_overrides = await loadOverrides(env.INTELLIGENCE_DB); },
      async key_controls() { installed.key_controls = await loadAccounts(env.INTELLIGENCE_DB); },
      async model_grants() { installed.model_grants = await loadAccounts(env.INTELLIGENCE_DB); },
    };
    const consumer = new RevisionConsumer(env, { ...options, refreshers });
    entry = { consumer, installed };
    consumers.set(env, entry);
  }
  return entry.consumer;
}

export function tickNativeRevisionSync(env, ctx) {
  const consumer = nativeRevisionConsumer(env);
  if (!consumer) return;
  const polling = consumer.tick().catch(() => {});
  ctx?.waitUntil?.(polling);
}
