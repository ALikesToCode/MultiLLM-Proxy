import { fail } from "./contracts.mjs";
import { resolveRetentionPolicy, retentionAllowsContent } from "../retention-policy.mjs";
import { digest } from "./evidence.mjs";
import { memoKey, memoQueryNorm, memoSecretQuery, quantizeEmbedding, MEMO_BUNDLE_BYTES } from "./memo-store.mjs";

const MEMO_TIMEOUT_MS = 2000;
const EXACT_TIMEOUT_MS = 300;
const SEMANTIC_TIMEOUT_MS = 400;
const nowIso = () => new Date().toISOString();

// A slow optional memo backend must leave time for ordinary retrieval.
async function bounded(callback, deadline = performance.now() + MEMO_TIMEOUT_MS) {
  const remaining = deadline - performance.now();
  if (remaining <= 0) throw new Error("memo_timeout");
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(callback), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("memo_timeout")), Math.min(MEMO_TIMEOUT_MS, remaining));
    })]);
  } finally { clearTimeout(timer); }
}

export function getMemos(env) {
  if (!env.KNOWLEDGE_MEMOS) return null;
  const stub = env.KNOWLEDGE_MEMOS.get(env.KNOWLEDGE_MEMOS.idFromName("personal"));
  return { async call(operation, payload = {}) {
    const response = await stub.fetch("http://memos.internal/dispatch", { method: "POST",
      headers: { "content-type": "application/json" }, body: JSON.stringify({ operation, payload }), signal: AbortSignal.timeout(MEMO_TIMEOUT_MS) });
    const result = await response.json();
    if (!response.ok || result.version !== 1) fail("memos_unavailable", "Knowledge memos are unavailable.", 503);
    return result.result;
  } };
}

class MemoSession {
  constructor(env, authority, request, policy, options, started, usage) {
    Object.assign(this, { env, authority, request, policy, options, started, usage });
    this.retentionPolicy = options.retentionPolicy ?? resolveRetentionPolicy(env, {
      keyId: options.retentionKeyId, keyHash: options.retentionKeyHash,
      route: options.retentionRoute, header: options.retentionHeader,
    });
    if (!retentionAllowsContent(this.retentionPolicy)) { this.enabled = false; return; }
    try { this.store = options.memos ?? getMemos(env); }
    catch { this.store = null; }
    this.enabled = this.store && !memoSecretQuery(request.query);
    this.exact = policy.memo_exact ?? "on";
    this.semantic = policy.memo_semantic ?? "observe";
  }

  deadline(milliseconds) {
    return performance.now() + Math.min(this.options.memoBudgetMs ?? milliseconds, milliseconds);
  }

  embedding() {
    return this.embeddingPromise ??= this.embed();
  }

  async embed() {
    if (!retentionAllowsContent(this.retentionPolicy)) return null;
    const { env, options, request, usage } = this;
    if (!options.embed && !env.KNOWLEDGE_SEARCH_AI?.run) return null;
    // Background completions must not mutate usage already returned to the caller.
    const entry = { provider: "workers_ai", operation_id: `${crypto.randomUUID()}:memo-embedding`, bound_units: 0,
      outcome: "unconfirmed", measurement: "unmetered_platform_operation" };
    usage.push(entry);
    try {
      const result = await bounded(() => options.embed ? options.embed(request.query)
        : env.KNOWLEDGE_SEARCH_AI.run("@cf/baai/bge-m3", { text: [request.query] }), this.deadline(MEMO_TIMEOUT_MS));
      const vector = Array.isArray(result) ? result : result?.data?.[0];
      const quantized = quantizeEmbedding(vector);
      if (quantized) entry.outcome = "completed";
      return quantized;
    } catch { return null; }
  }

  async validate(match, deadline) {
    if (!match) return null;
    const { record } = match;
    const age = (Date.now() - Date.parse(record.created_at)) / 1000;
    let valid = Number.isFinite(age) && age >= 0 && age < (this.policy.memo_ttl_hours ?? 72) * 3600
      && (record.state ?? null) === (this.options.memoState ?? null);
    if (valid) valid = (await bounded(() => this.authority.call("memos.validate", {
      citations: record.citations, policy_revision: this.policy.revision,
    }), deadline)).valid;
    if (!valid) { await bounded(() => this.store.call("delete", { id: record.id }), deadline); return null; }
    return { ...match, age_seconds: Math.floor(age) };
  }

  async findSemantic(deadline) {
    const vector = await bounded(() => this.embedding(), deadline);
    if (!vector) return null;
    const match = await bounded(() => this.store.call("find", {
      request: this.request, kind: "semantic", embedding: vector, similarity: this.policy.memo_similarity ?? 0.92,
    }), deadline);
    return this.validate(match, deadline);
  }

  async serve(match, kind, deadline) {
    await bounded(() => this.store.call("hit", { id: match.record.id }), deadline);
    const memo = { kind, similarity: match.similarity,
      ...(kind === "semantic" ? { matched_query: match.record.query } : {}), age_seconds: match.age_seconds };
    return { bundle: this.finish({ ...structuredClone(match.record.bundle), query: this.request.query,
      path: "memo", providers_used: [], served_at: nowIso(),
      elapsed_ms: Math.round(performance.now() - this.started), memo }) };
  }

  keepAlive(promise) {
    try { this.options.waitUntil?.(promise); }
    catch { /* Optional background registration must not fail retrieval. */ }
  }

  async lookup() {
    if (!this.enabled || this.request.freshness !== "normal" || this.exact === "off" && this.semantic === "off") return {};
    if (this.exact === "on") {
      const deadline = this.deadline(EXACT_TIMEOUT_MS);
      try {
        const match = await this.validate(await bounded(() => this.store.call("find", {
          request: this.request, kind: "exact",
        }), deadline), deadline);
        if (match) return await this.serve(match, "exact", deadline);
      } catch { /* A slow or failed exact lookup is a miss. */ }
    }
    if (this.semantic === "off") return {};
    const deadline = this.deadline(this.semantic === "observe" ? MEMO_TIMEOUT_MS : SEMANTIC_TIMEOUT_MS);
    if (this.semantic === "observe") {
      const observation = this.findSemantic(deadline).then(match => {
        if (match && !this.assembled) this.candidate = { similarity: match.similarity,
          matched_query: match.record.query, age_seconds: match.age_seconds };
      }).catch(() => {});
      // Keep the bounded observation alive without waiting for its result.
      this.keepAlive(observation);
      return {};
    }
    try {
      const match = await this.findSemantic(deadline);
      return match ? await this.serve(match, "semantic", deadline) : {};
    } catch { return {}; }
  }

  assembledBundle(bundle) {
    this.assembled = true;
    if (this.candidate) bundle.index_diagnostics = { ...(bundle.index_diagnostics || {}), memo_candidate: this.candidate };
    return bundle;
  }

  finish(bundle) {
    return { ...bundle, usage: this.usage.map(entry => ({ ...entry })) };
  }

  async storeBundle(bundle) {
    if (!retentionAllowsContent(this.retentionPolicy)) return;
    const deadline = Math.min(this.deadline(MEMO_TIMEOUT_MS),
      this.options.waitUntil ? Infinity : this.options.memoWriteDeadlineAt ?? Infinity);
    if (deadline <= performance.now()) return;
    const saved = structuredClone(bundle);
    for (const name of ["usage", "served_at", "memo"]) delete saved[name];
    if (saved.index_diagnostics?.memo_candidate) delete saved.index_diagnostics.memo_candidate;
    if (new TextEncoder().encode(JSON.stringify(saved)).byteLength > MEMO_BUNDLE_BYTES) return;
    const citations = [...new Map([...saved.excerpts, ...(saved.related_evidence || [])].map(item => [item.artifact_id,
      { artifact_id: item.artifact_id, content_hash: item.content_hash, expires_at: item.expires_at }])).values()];
    // Memo backing follows the same live and published eligibility rules as retrieval.
    if (!(await bounded(() => this.authority.call("memos.validate", {
      citations, policy_revision: this.policy.revision,
    }), deadline)).valid) return;
    const vector = this.semantic !== "off" ? await bounded(() => this.embedding(), deadline) : null;
    const key = memoKey(this.request);
    const queryNorm = memoQueryNorm(this.request.query);
    const time = nowIso();
    const record = { id: await digest(JSON.stringify([key, queryNorm, this.request.mode, bundle.token_count])), created_at: time,
      last_hit_at: time, hits: 0, key, query: this.request.query, query_norm: queryNorm, mode: this.request.mode,
      token_budget: this.request.token_budget, embedding: vector, bundle: saved, citations,
      ...(this.options.memoState ? { state: this.options.memoState } : {}) };
    await bounded(() => this.store.call("put", { record }), deadline);
  }

  async write(bundle, failed) {
    if (!retentionAllowsContent(this.retentionPolicy) || !this.enabled || failed || this.exact === "off" && this.semantic === "off"
      || !["ok", "partial"].includes(bundle.status) || !bundle.excerpts?.length) return;
    // Validation, embedding and storage all belong to the background task.
    const write = Promise.resolve().then(() => this.storeBundle(bundle)).catch(() => {});
    if (this.options.waitUntil) this.keepAlive(write);
    else await write;
  }
}

export function memoSession(env, authority, request, policy, options, started, usage) {
  return new MemoSession(env, authority, request, policy, options, started, usage);
}
