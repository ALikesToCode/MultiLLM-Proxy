import { fail } from "./contracts.mjs";
import { digest } from "./evidence.mjs";
import { parseFind, parseGet, parseSync, validateSkill, skillKey, SKILLS_LIMIT } from "./skills-validation.mjs";
import { quantizeEmbedding } from "./memo-store.mjs";
import { SkillsIndex } from "./skills-index.mjs";

const SUGGESTION_LIMIT = 5000;
const CLEANUP_LIMIT = 64;
const CLEANUP_GRACE_MS = 60000;
const HELPFUL_MS = 30 * 60 * 1000;
const cap = number => Math.min(Number.MAX_SAFE_INTEGER, number + 1);
async function bounded(callback, milliseconds) {
  let timer;
  try { return await Promise.race([Promise.resolve().then(callback), new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("skills_timeout")), milliseconds);
  })]); } finally { clearTimeout(timer); }
}
export class SkillsStore {
  constructor(storage, env, { embed, clock = Date.now } = {}) {
    Object.assign(this, { storage, sql: storage.sql, env, clock });
    this.embed = embed ?? (text => env.KNOWLEDGE_SEARCH_AI?.run("@cf/baai/bge-m3", { text: [text] }));
    this.index = null;
    this.syncTail = Promise.resolve();
    this.pendingR2 = new Map();
    this.sql.exec(`CREATE TABLE IF NOT EXISTS skills (skill_id TEXT PRIMARY KEY, root TEXT NOT NULL,
      record TEXT NOT NULL, suggested INTEGER NOT NULL, fetched INTEGER NOT NULL, helpful INTEGER NOT NULL)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS skill_suggestions (principal TEXT NOT NULL, skill_id TEXT NOT NULL,
      at INTEGER NOT NULL, PRIMARY KEY (principal, skill_id))`);
    this.sql.exec("CREATE INDEX IF NOT EXISTS skill_suggestion_age ON skill_suggestions(at)");
    this.sql.exec(`CREATE TABLE IF NOT EXISTS skill_cleanup (skill_id TEXT NOT NULL, content_hash TEXT NOT NULL,
      record TEXT NOT NULL, after INTEGER NOT NULL, PRIMARY KEY (skill_id, content_hash))`);
  }
  rows(sql, ...args) { return [...this.sql.exec(sql, ...args)]; }
  read(id) {
    const row = this.rows("SELECT * FROM skills WHERE skill_id = ?", id)[0];
    return row ? { ...JSON.parse(row.record), suggested: row.suggested, fetched: row.fetched, helpful: row.helpful } : null;
  }
  getIndex() {
    if (!this.index) this.index = new SkillsIndex(this.rows("SELECT * FROM skills ORDER BY skill_id LIMIT ?", SKILLS_LIMIT)
      .map(row => ({ ...JSON.parse(row.record), suggested: row.suggested, fetched: row.fetched, helpful: row.helpful })), { confidentCosine: this.env.SKILLS_CONFIDENT_COSINE });
    return this.index;
  }
  async embedding(text) {
    try {
      const result = await bounded(() => this.embed(text), 350);
      return quantizeEmbedding(Array.isArray(result) ? result : result?.data?.[0]);
    } catch { return null; }
  }
  async find(payload, principal) {
    const parsed = parseFind(payload);
    const embedding = parsed.mode === "hybrid" ? await this.embedding(parsed.query) : null;
    const results = this.getIndex().find(parsed, embedding);
    const now = this.clock(), identity = await digest(principal);
    this.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM skill_suggestions WHERE at < ?", now - HELPFUL_MS);
      for (const result of results) {
        this.sql.exec("UPDATE skills SET suggested = MIN(suggested + 1, 9007199254740991) WHERE skill_id = ?", result.skill_id);
        this.sql.exec("INSERT OR REPLACE INTO skill_suggestions VALUES (?, ?, ?)", identity, result.skill_id, now);
      }
      const count = this.rows("SELECT COUNT(*) AS count FROM skill_suggestions")[0].count;
      this.sql.exec(`DELETE FROM skill_suggestions WHERE rowid IN
        (SELECT rowid FROM skill_suggestions ORDER BY at, rowid LIMIT ?)`, Math.max(0, count - SUGGESTION_LIMIT));
    });
    return results;
  }
  async get(payload, principal) {
    const parsed = parseGet(payload), record = this.read(parsed.skill_id);
    if (!record) fail("skill_missing", "The skill was not found.", 404);
    const file = record.files.find(item => item.path === parsed.path);
    if (!file) fail("file_missing", "The skill file was not found.", 404);
    const object = await bounded(() => this.env.KNOWLEDGE_SNAPSHOTS.get(skillKey(record, parsed.path)), 3000);
    if (!object) fail("file_missing", "The skill file is unavailable.", 404);
    const bytes = new Uint8Array(await bounded(() => object.arrayBuffer(), 3000));
    if (bytes.length !== file.size || await digest(bytes) !== file.sha256) fail("skill_corrupt", "The skill file failed its integrity check.", 503);
    const identity = await digest(principal), now = this.clock();
    this.storage.transactionSync(() => {
      const current = this.read(parsed.skill_id);
      if (!current || current.content_hash !== record.content_hash) fail("skill_changed", "The skill changed while reading.", 409);
      const suggestion = this.rows("SELECT at FROM skill_suggestions WHERE principal = ? AND skill_id = ?", identity, record.skill_id)[0];
      const helpful = suggestion && now >= suggestion.at && now - suggestion.at <= HELPFUL_MS;
      this.sql.exec("UPDATE skills SET fetched = ?, helpful = ? WHERE skill_id = ?", cap(current.fetched), helpful ? cap(current.helpful) : current.helpful, record.skill_id);
      this.sql.exec("DELETE FROM skill_suggestions WHERE principal = ? AND skill_id = ?", identity, record.skill_id);
      const cached = this.index?.records.find(item => item.skill_id === record.skill_id);
      if (cached && helpful) cached.helpful = cap(current.helpful);
    });
    const response = { skill_id: record.skill_id, path: parsed.path, files: record.files.map(item => item.path), content_hash: record.content_hash, trust: "operator" };
    try { return { ...response, text: new TextDecoder("utf-8", { fatal: true }).decode(bytes) }; }
    catch { return { ...response, content_base64: btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join("")) }; }
  }
  enqueueCleanup(record) {
    if (this.rows("SELECT COUNT(*) AS count FROM skill_cleanup")[0].count >= CLEANUP_LIMIT
      && !this.rows("SELECT 1 FROM skill_cleanup WHERE skill_id = ? AND content_hash = ?", record.skill_id, record.content_hash).length)
      fail("cleanup_backlog", "Retry after pending skill file cleanup completes.", 503);
    const revision = { skill_id: record.skill_id, content_hash: record.content_hash, files: record.files.map(({ path }) => ({ path })) };
    this.sql.exec("INSERT OR REPLACE INTO skill_cleanup VALUES (?, ?, ?, ?)", record.skill_id, record.content_hash,
      JSON.stringify(revision), this.clock() + CLEANUP_GRACE_MS);
  }
  r2(record, callback) {
    const key = skillKey(record, "");
    if (this.pendingR2.has(key)) fail("cleanup_backlog", "A skill storage operation is still pending.", 503);
    const promise = Promise.resolve().then(callback);
    this.pendingR2.set(key, promise);
    const settled = () => { if (this.pendingR2.get(key) === promise) this.pendingR2.delete(key); };
    promise.then(settled, settled);
    return promise;
  }
  async cleanup(deadline) {
    const pending = this.rows("SELECT * FROM skill_cleanup WHERE after <= ? LIMIT ?", this.clock(), CLEANUP_LIMIT);
    for (const row of pending) {
      if (performance.now() >= deadline) break;
      const current = this.read(row.skill_id);
      // Timed-out R2 promises may still finish: never delete or reuse their revision.
      if (this.pendingR2.has(skillKey(row, ""))) continue;
      try {
        if (current?.content_hash !== row.content_hash) {
          const revision = JSON.parse(row.record);
          await bounded(() => this.r2(revision, () => this.env.KNOWLEDGE_SNAPSHOTS.delete(revision.files.map(file => skillKey(revision, file.path)))),
            Math.min(3000, deadline - performance.now()));
        }
        this.sql.exec("DELETE FROM skill_cleanup WHERE skill_id = ? AND content_hash = ?", row.skill_id, row.content_hash);
      } catch { break; } // Retain receipts and apply backpressure if R2 cleanup is unavailable.
    }
  }
  async syncSkill(skill, dryRun, deadline) {
    const validated = await validateSkill(skill);
    if (validated.rejected) return { skill_id: skill.skill_id, status: "rejected", ...validated.rejected };
    const { record, files } = validated, old = this.read(record.skill_id);
    if (old && old.root !== record.root) return { skill_id: record.skill_id, status: "rejected", reason: "root_conflict" };
    const status = !old ? "created" : old.content_hash === record.content_hash ? "unchanged" : "updated";
    if (status === "unchanged" || dryRun) return { skill_id: record.skill_id, status };
    if (!old && this.rows("SELECT COUNT(*) AS count FROM skills")[0].count >= SKILLS_LIMIT) return { skill_id: record.skill_id, status: "rejected", reason: "skills_limit" };
    if (this.pendingR2.has(skillKey(record, ""))) return { skill_id: record.skill_id, status: "rejected", reason: "cleanup_backlog" };
    // Receipts cap pending R2 promises as well as interrupted revision storage.
    this.enqueueCleanup(record);
    record.embedding = await this.embedding(`${record.name}: ${record.description}`);
    record.updated_at = new Date(this.clock()).toISOString();
    for (const file of files) {
      if (performance.now() >= deadline) throw new Error("skills_timeout");
      await bounded(() => this.r2(record, () => this.env.KNOWLEDGE_SNAPSHOTS.put(skillKey(record, file.path), file.bytes)), Math.min(3000, deadline - performance.now()));
    }
    if (performance.now() >= deadline) throw new Error("skills_timeout");
    this.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM skill_cleanup WHERE skill_id = ? AND content_hash = ?", record.skill_id, record.content_hash);
      if (old) this.enqueueCleanup(old);
      // Reads can update feedback while R2 uploads are in flight.
      const current = this.read(record.skill_id);
      this.sql.exec("INSERT OR REPLACE INTO skills VALUES (?, ?, ?, ?, ?, ?)", record.skill_id, record.root, JSON.stringify(record), current?.suggested ?? 0, current?.fetched ?? 0, current?.helpful ?? 0);
    });
    this.index = null;
    return { skill_id: record.skill_id, status };
  }
  async sync(payload) {
    const parsed = parseSync(payload), results = [];
    const deadline = performance.now() + 45000;
    if (!parsed.dry_run) await this.cleanup(deadline);
    let count = this.rows("SELECT COUNT(*) AS count FROM skills")[0].count;
    for (const skill of parsed.skills) {
      try {
        if (performance.now() >= deadline) throw new Error("skills_timeout");
        if (parsed.dry_run && !this.read(skill.skill_id) && count >= SKILLS_LIMIT) results.push({ skill_id: skill.skill_id, status: "rejected", reason: "skills_limit" });
        else {
          const result = await this.syncSkill(skill, parsed.dry_run, deadline);
          if (result.status === "created") count++;
          results.push(result);
        }
      } catch (error) {
        results.push({ skill_id: skill.skill_id, status: "rejected", reason: error.code ?? "skills_unavailable" });
      }
    }
    for (const id of parsed.delete) {
      const found = this.read(id);
      try {
        if (!parsed.dry_run && found) this.storage.transactionSync(() => {
          this.enqueueCleanup(found);
          this.sql.exec("DELETE FROM skills WHERE skill_id = ?", id);
          this.sql.exec("DELETE FROM skill_suggestions WHERE skill_id = ?", id);
        });
        results.push({ skill_id: id, status: found ? "deleted" : "unchanged" });
      } catch (error) { results.push({ skill_id: id, status: "rejected", reason: error.code ?? "skills_unavailable" }); }
    }
    if (!parsed.dry_run && parsed.delete.length) this.index = null;
    return { results };
  }
  async call(operation, payload, principal) {
    if (operation === "find") return this.find(payload, principal);
    if (operation === "get") return this.get(payload, principal);
    if (operation === "sync") {
      const task = this.syncTail.then(() => this.sync(payload));
      this.syncTail = task.catch(() => {});
      return task;
    }
    fail("unknown_operation", "Unknown skills operation.", 404);
  }
}
