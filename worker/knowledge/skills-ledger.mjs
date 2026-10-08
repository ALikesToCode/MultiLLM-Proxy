import { fail, fields, integer, isRecord } from "./contracts.mjs";
import { slug } from "./skills-validation.mjs";

// Marketplace health, library gaps and upstream checks of imported skills. Nothing here
// changes which skills are served; it only shapes discovery and the operator's reports.
const TRIP_FAILURES = 3;
const COOLDOWN_MS = 10 * 60 * 1000;
const GAP_LIMIT = 500;
const GAP_MS = 90 * 24 * 60 * 60 * 1000;
const WATCH_MS = 24 * 60 * 60 * 1000;
const REPORT_BYTES = 96 * 1024;
const HEALTHY = new Set(["ok", "not_configured"]);
const FAILED = new Set(["timeout", "rate_limited", "access_denied", "error"]);
const bounded = (value, maximum) => typeof value === "string" ? value.slice(0, maximum) : "";
const iso = at => at ? new Date(at).toISOString() : null;
export const pinOf = origin => origin?.commit ?? origin?.version ?? null;
export function publicOrigin(origin) {
  if (!isRecord(origin)) return undefined;
  const { source, repository, path, ref, commit, clawhub, version, imported_at, accepted_flags } = origin;
  return source === "github" ? { source, repository, path, ref, commit, imported_at, accepted_flags }
    : { source, clawhub, version, imported_at, accepted_flags };
}

export class SkillsLedger {
  constructor(storage, clock) {
    Object.assign(this, { storage, sql: storage.sql, clock });
    this.sql.exec(`CREATE TABLE IF NOT EXISTS market_health (source TEXT PRIMARY KEY, failures INTEGER NOT NULL,
      until INTEGER NOT NULL, status TEXT NOT NULL, at INTEGER NOT NULL)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS skill_gaps (query TEXT PRIMARY KEY, count INTEGER NOT NULL,
      first_at INTEGER NOT NULL, last_at INTEGER NOT NULL, candidates TEXT NOT NULL)`);
    this.sql.exec("CREATE INDEX IF NOT EXISTS skill_gap_age ON skill_gaps(last_at)");
    this.sql.exec(`CREATE TABLE IF NOT EXISTS skill_watch (skill_id TEXT PRIMARY KEY, pin TEXT NOT NULL,
      checked_at INTEGER NOT NULL, status TEXT NOT NULL, report TEXT NOT NULL)`);
  }
  rows(sql, ...args) { return [...this.sql.exec(sql, ...args)]; }
  imported() {
    return this.rows("SELECT record FROM skills WHERE root = 'imported' ORDER BY skill_id").map(row => JSON.parse(row.record));
  }

  // Sources that failed repeatedly, or hit a rate limit, sit out a cooldown instead of slowing every search.
  state() {
    const now = this.clock();
    return { skipped: this.rows("SELECT source, until FROM market_health WHERE until > ? ORDER BY source", now)
      .map(row => ({ id: row.source, retry_after: Math.ceil((row.until - now) / 1000) })) };
  }

  record(payload) {
    fields(payload, ["outcomes", "candidates", "gap", "resolved"]);
    const outcomes = payload.outcomes ?? [], candidates = payload.candidates ?? [];
    if (!Array.isArray(outcomes) || outcomes.length > 20 || !Array.isArray(candidates) || candidates.length > 20) fail("invalid_request", "Invalid discovery record.");
    const now = this.clock();
    this.storage.transactionSync(() => {
      for (const outcome of outcomes) {
        const id = bounded(outcome?.id, 40), status = outcome?.status;
        if (HEALTHY.has(status)) this.sql.exec("DELETE FROM market_health WHERE source = ?", id);
        if (!id || !FAILED.has(status)) continue;
        const failures = (this.rows("SELECT failures FROM market_health WHERE source = ?", id)[0]?.failures ?? 0) + 1;
        const until = status === "rate_limited" || failures >= TRIP_FAILURES ? now + COOLDOWN_MS : 0;
        this.sql.exec("INSERT OR REPLACE INTO market_health VALUES (?, ?, ?, ?, ?)", id, Math.min(failures, 1000), until, status, now);
      }
      if (typeof payload.resolved === "string") this.sql.exec("DELETE FROM skill_gaps WHERE query = ?", bounded(payload.resolved, 200));
      if (isRecord(payload.gap) && typeof payload.gap.query === "string" && payload.gap.query) {
        const shown = (Array.isArray(payload.gap.candidates) ? payload.gap.candidates : []).slice(0, 3)
          .map(item => ({ name: bounded(item?.name, 100), url: bounded(item?.url, 300), install: bounded(item?.install, 200) }));
        // A later search with every marketplace down keeps the earlier suggestions.
        this.sql.exec(`INSERT INTO skill_gaps VALUES (?, 1, ?, ?, ?) ON CONFLICT(query) DO UPDATE SET
          count = MIN(count + 1, 9007199254740991), last_at = excluded.last_at,
          candidates = CASE WHEN excluded.candidates = '[]' THEN candidates ELSE excluded.candidates END`,
        bounded(payload.gap.query, 200), now, now, JSON.stringify(shown));
        this.sql.exec("DELETE FROM skill_gaps WHERE last_at < ?", now - GAP_MS);
        const count = this.rows("SELECT COUNT(*) AS count FROM skill_gaps")[0].count;
        if (count > GAP_LIMIT) this.sql.exec("DELETE FROM skill_gaps WHERE rowid IN (SELECT rowid FROM skill_gaps ORDER BY last_at, rowid LIMIT ?)", count - GAP_LIMIT);
      }
    });
    return { installed: this.installed(candidates) };
  }

  // Imported skills match their exact origin; any library skill matches a candidate with its name.
  installed(candidates) {
    const imported = this.imported();
    return candidates.map(candidate => {
      if (!isRecord(candidate) || typeof candidate.name !== "string") return null;
      const id = slug(candidate.name).slice(0, 100);
      const origin = imported.find(({ skill_id: skillId, origin: item }) => typeof candidate.clawhub === "string"
        ? item?.source === "clawhub" && item.clawhub.toLowerCase() === candidate.clawhub.toLowerCase()
        : typeof candidate.repository === "string" && item?.source === "github"
          && item.repository.toLowerCase() === candidate.repository.toLowerCase()
          && (typeof candidate.path === "string" ? candidate.path === item.path : skillId === id));
      if (origin) return { skill_id: origin.skill_id, root: "imported", match: "imported" };
      const row = id && this.rows("SELECT root FROM skills WHERE skill_id = ?", id)[0];
      return row ? { skill_id: id, root: row.root, match: "same_name" } : null;
    });
  }

  gaps(limit) {
    return this.rows("SELECT * FROM skill_gaps ORDER BY count DESC, last_at DESC LIMIT ?", limit).map(row => ({
      query: row.query, count: row.count, first_seen: iso(row.first_at), last_seen: iso(row.last_at), candidates: JSON.parse(row.candidates) }));
  }

  // Never-checked imports first, then the oldest checks; a new pin makes an import due again.
  due({ limit, force }) {
    const now = this.clock();
    const watch = new Map(this.rows("SELECT skill_id, pin, checked_at FROM skill_watch").map(row => [row.skill_id, row]));
    return this.imported().map(record => ({ record, seen: watch.get(record.skill_id) }))
      .filter(({ record, seen }) => force || !seen || seen.pin !== pinOf(record.origin) || seen.checked_at <= now - WATCH_MS)
      .sort((a, b) => (a.seen?.checked_at ?? 0) - (b.seen?.checked_at ?? 0) || a.record.skill_id.localeCompare(b.record.skill_id))
      .slice(0, limit)
      .map(({ record }) => ({ skill_id: record.skill_id, content_hash: record.content_hash, origin: record.origin, files: record.files }));
  }

  checked({ skill_id: skillId, pin, result }) {
    const row = this.rows("SELECT record FROM skills WHERE skill_id = ? AND root = 'imported'", skillId)[0];
    // An import re-pinned during the check makes this result stale.
    if (!row || pinOf(JSON.parse(row.record).origin) !== pin || !isRecord(result) || typeof result.status !== "string") return { stored: false };
    let report = JSON.stringify(result);
    if (report.length > REPORT_BYTES) {
      report = JSON.stringify({ ...result, changes: (result.changes ?? []).map(({ diff, ...change }) => change), diffs_omitted: true }).slice(0, REPORT_BYTES);
    }
    this.sql.exec("INSERT OR REPLACE INTO skill_watch VALUES (?, ?, ?, ?, ?)", skillId, pin, this.clock(), bounded(result.status, 20), report);
    return { stored: true };
  }

  updates(limit) {
    const watch = new Map(this.rows("SELECT * FROM skill_watch").map(row => [row.skill_id, row]));
    return this.imported().slice(0, limit).map(record => {
      const seen = watch.get(record.skill_id), pinned = seen?.pin === pinOf(record.origin);
      const report = pinned ? JSON.parse(seen.report) : {};
      return { skill_id: record.skill_id, name: record.name, origin: publicOrigin(record.origin),
        ...report, status: pinned ? seen.status : "unchecked", checked_at: pinned ? iso(seen.checked_at) : null };
    });
  }

  forget(skillId) { this.sql.exec("DELETE FROM skill_watch WHERE skill_id = ?", skillId); }

  call(operation, payload) {
    if (operation === "market.state") return this.state();
    if (operation === "market.record") return this.record(payload);
    if (operation === "imports.due") return this.due({ limit: integer(payload?.limit ?? 5, 1, 20, "limit"), force: payload?.force === true });
    if (operation === "imports.checked") return this.checked(payload ?? {});
    if (operation === "report.gaps") return this.gaps(integer(payload?.limit ?? 20, 1, 50, "limit"));
    if (operation === "report.updates") return this.updates(integer(payload?.limit ?? 20, 1, 50, "limit"));
    fail("unknown_operation", "Unknown skills operation.", 404);
  }
}
