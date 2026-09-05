const KEY = "operator_traces_v1";
const LIMIT = 30;
const TTL_MS = 24 * 60 * 60 * 1000;
const NUMBERS = ["queueMs", "headerMs", "firstReasoningMs", "firstContentMs",
  "tokensPerSecond", "completionTokens", "upstreamCallCount", "continuationCount"];

// No payloads, credentials, session names, or provider error messages belong here.
export class TurnTraceJournal {
  constructor(storage) {
    this.storage = storage;
    this.records = [];
    this.writes = Promise.resolve();
    this.ready = storage.get(KEY).then((rows) => {
      this.records = (Array.isArray(rows) ? rows : []).filter((row) =>
        row.startedAt > Date.now() - TTL_MS).slice(-LIMIT);
    }).catch(() => {});
  }

  begin() {
    const row = { id: crypto.randomUUID(), startedAt: Date.now(),
      phase: "queued", events: [], metrics: {} };
    this.records.push(row);
    this.records = this.records.slice(-LIMIT);
    const phase = (name) => {
      if (row.finishedAt || row.events.some((event) => event.phase === name)) return;
      row.phase = name;
      row.events.push({ phase: name, elapsedMs: Date.now() - row.startedAt });
    };
    const metrics = (values) => {
      for (const key of NUMBERS) {
        if (Number.isFinite(values?.[key]) && values[key] >= 0) row.metrics[key] = values[key];
      }
    };
    phase("queued");
    return {
      id: row.id, phase, metrics,
      selected(candidate, receipt) {
        row.provider = candidate.provider;
        row.model = candidate.model;
        row.parameters = receipt;
      },
      progress(values) {
        metrics(values);
        if (Number.isFinite(values.firstReasoningMs)) phase("reasoning");
        if (Number.isFinite(values.firstContentMs)) phase("visible");
      },
      finish: async (success, reason = "failed", persist = null) => {
        if (row.finishedAt) return;
        phase(success ? "completed" : "interrupted");
        row.finishedAt = Date.now();
        row.reason = /^[a-z0-9_]{1,64}$/.test(reason) ? reason : "failed";
        const completed = this.records.filter((item) => item.finishedAt);
        this.writes = this.writes.catch(() => {}).then(() => persist ? persist({ [KEY]: completed }) : this.storage.put(KEY, completed));
        try { await this.writes; } catch (error) {
          row.diagnosticsPersisted = false;
          if (persist) { delete row.finishedAt; throw error; }
        }
      },
    };
  }

  snapshot() {
    return { scope: "roleplay_session", retention: "30 completed turns, 24 hours; active turns are runtime-local",
      records: structuredClone(this.records.filter((row) => row.startedAt > Date.now() - TTL_MS)) };
  }

  clear() { this.records = []; }
}
