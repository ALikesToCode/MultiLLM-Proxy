/** Fixed private operations for the optional text screen's revision-checked settings. */
const fields = (body, names) => Object.keys(body).length === names.length && names.every(key => Object.hasOwn(body, key));
const reply = (settings) => Response.json({ version: 1, settings: {
  enabled: settings.enabled === 1, failure_mode: settings.failure_mode, revision: settings.revision,
} }, { headers: { "cache-control": "no-store" } });

export async function handleChildSafetySettings(db, body) {
  if (body.operation === "get") {
    if (!fields(body, ["version", "operation"])) return null;
    const row = await db.prepare("SELECT enabled, failure_mode, revision FROM control_child_safety_settings WHERE id = 1").first();
    if (!row) throw new Error("Safety settings unavailable");
    return reply(row);
  }
  if (body.operation !== "configure" || !fields(body, ["version", "operation", "enabled", "failure_mode", "revision"])
      || typeof body.enabled !== "boolean" || !["allow", "block"].includes(body.failure_mode)
      || !Number.isSafeInteger(body.revision) || body.revision < 0 || body.revision === Number.MAX_SAFE_INTEGER) return null;
  const row = await db.prepare(`UPDATE control_child_safety_settings SET enabled = ?, failure_mode = ?, revision = revision + 1
    WHERE id = 1 AND revision = ? RETURNING enabled, failure_mode, revision`)
    .bind(Number(body.enabled), body.failure_mode, body.revision).first();
  if (!row) return Response.json({ version: 1, error: { code: "safety_settings_conflict" } },
    { status: 409, headers: { "cache-control": "no-store" } });
  return reply(row);
}
