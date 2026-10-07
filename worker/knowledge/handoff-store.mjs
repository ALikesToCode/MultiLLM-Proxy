import { fail } from "./contracts.mjs";
import { HANDOFF_BYTES, handoffBytes, parseHandoff, renderHandoff } from "./handoff-contracts.mjs";

export const HANDOFF_PROJECT_LIMIT = 50;
export const HANDOFF_PRINCIPAL_LIMIT = 500;

// Each principal has its own SQLite object; eviction and insertion share a transaction.
export class HandoffStore {
  constructor(storage, { projectLimit = HANDOFF_PROJECT_LIMIT, totalLimit = HANDOFF_PRINCIPAL_LIMIT } = {}) {
    this.storage = storage;
    this.sql = storage.sql;
    this.projectLimit = projectLimit;
    this.totalLimit = totalLimit;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS handoffs (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, project TEXT NOT NULL,
      branch TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, record TEXT NOT NULL)`);
    this.sql.exec("CREATE INDEX IF NOT EXISTS handoff_project ON handoffs(project, branch, sequence)");
    this.sql.exec("CREATE INDEX IF NOT EXISTS handoff_expiry ON handoffs(expires_at)");
  }

  rows(query, ...args) { return [...this.sql.exec(query, ...args)]; }

  save(parsed, now) {
    const { ttl_days, ...content } = parsed;
    const record = { id: crypto.randomUUID(), ...content, created_at: new Date(now).toISOString(),
      expires_at: new Date(now + ttl_days * 86400000).toISOString() };
    if (handoffBytes(record) > HANDOFF_BYTES) fail("invalid_request", "The handoff record exceeds 32 KB.");
    this.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM handoffs WHERE expires_at <= ?", record.created_at);
      this.sql.exec("INSERT INTO handoffs (id, project, branch, created_at, expires_at, record) VALUES (?, ?, ?, ?, ?, ?)",
        record.id, record.project, record.branch, record.created_at, record.expires_at, JSON.stringify(record));
      this.sql.exec(`DELETE FROM handoffs WHERE project = ? COLLATE NOCASE AND sequence NOT IN
        (SELECT sequence FROM handoffs WHERE project = ? COLLATE NOCASE ORDER BY sequence DESC LIMIT ?)`, record.project, record.project, this.projectLimit);
      this.sql.exec("DELETE FROM handoffs WHERE sequence NOT IN (SELECT sequence FROM handoffs ORDER BY sequence DESC LIMIT ?)", this.totalLimit);
    });
    return { id: record.id, expires_at: record.expires_at, trust: "operator" };
  }

  get(payload, time) {
    const where = payload.project === undefined ? "expires_at > ?" : "project = ? COLLATE NOCASE AND expires_at > ?";
    const args = payload.project === undefined ? [time] : [payload.project, time];
    let row;
    if (payload.id !== undefined) row = this.rows(`SELECT record FROM handoffs WHERE ${where} AND id = ? LIMIT 1`, ...args, payload.id)[0];
    else {
      if (payload.branch !== undefined) row = this.rows(`SELECT record FROM handoffs WHERE ${where} AND branch = ? ORDER BY sequence DESC LIMIT 1`, ...args, payload.branch)[0];
      row ??= this.rows(`SELECT record FROM handoffs WHERE ${where} ORDER BY sequence DESC LIMIT 1`, ...args)[0];
    }
    const record = row ? JSON.parse(row.record) : null;
    return { record, markdown: record ? renderHandoff(record) : "", trust: "operator" };
  }

  list(payload, time) {
    const where = payload.project === undefined ? "expires_at > ?" : "expires_at > ? AND project = ? COLLATE NOCASE";
    const args = payload.project === undefined ? [time] : [time, payload.project];
    const handoffs = this.rows(`SELECT record FROM handoffs WHERE ${where} ORDER BY sequence DESC LIMIT ?`, ...args, payload.limit)
      .map(row => { const { id, project, branch, title, source, created_at } = JSON.parse(row.record);
        return { id, project, branch, title, source: { agent: source.agent }, created_at }; });
    return { handoffs, trust: "operator" };
  }

  call(operation, payload, now = Date.now()) {
    const parsed = parseHandoff(operation, payload);
    if (operation === "save") return this.save(parsed, now);
    if (operation === "get") return this.get(parsed, new Date(now).toISOString());
    if (operation === "list") return this.list(parsed, new Date(now).toISOString());
    const deleted = this.rows("SELECT id FROM handoffs WHERE id = ? LIMIT 1", parsed.id).length > 0;
    this.sql.exec("DELETE FROM handoffs WHERE id = ?", parsed.id);
    return { deleted, trust: "operator" };
  }
}
