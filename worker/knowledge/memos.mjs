import { fail } from "./contracts.mjs";
import { digest } from "./evidence.mjs";
import { memoKey, memoQueryNorm, memoSecretQuery, quantizeEmbedding, MEMO_BUNDLE_BYTES } from "./memo-store.mjs";

const MEMO_TIMEOUT_MS = 2000;
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

export function memoSession(env, authority, request, policy, options, started, usage) {
  let store;
  try { store = options.memos ?? getMemos(env); }
  catch { store = null; }
  const enabled = store && !memoSecretQuery(request.query);
  const exact = policy.memo_exact ?? "on";
  const semantic = policy.memo_semantic ?? "observe";
  let deadline;
  const budget = Math.min(options.memoBudgetMs ?? MEMO_TIMEOUT_MS, MEMO_TIMEOUT_MS);
  const optional = callback => bounded(callback, deadline);
  let embeddingPromise;
  const embedding = () => embeddingPromise ??= (async () => {
    if (!options.embed && !env.KNOWLEDGE_SEARCH_AI?.run) return null;
    let completed = false;
    try {
      const result = await optional(() => options.embed ? options.embed(request.query)
        : env.KNOWLEDGE_SEARCH_AI.run("@cf/baai/bge-m3", { text: [request.query] }));
      const vector = Array.isArray(result) ? result : result?.data?.[0];
      const quantized = quantizeEmbedding(vector);
      completed = Boolean(quantized);
      return quantized;
    } catch { return null; }
    finally {
      // Workers AI embeddings have no existing reservation tariff in the gateway.
      usage.push({ provider: "workers_ai", operation_id: `${crypto.randomUUID()}:memo-embedding`, bound_units: 0,
        outcome: completed ? "completed" : "unconfirmed", measurement: "unmetered_platform_operation" });
    }
  })();
  const validate = async match => {
    if (!match) return null;
    const { record } = match;
    const age = (Date.now() - Date.parse(record.created_at)) / 1000;
    let valid = Number.isFinite(age) && age >= 0 && age < (policy.memo_ttl_hours ?? 72) * 3600;
    if (valid) valid = (await optional(() => authority.call("memos.validate", {
      citations: record.citations, policy_revision: policy.revision,
    }))).valid;
    if (!valid) { await optional(() => store.call("delete", { id: record.id })); return null; }
    return { ...match, age_seconds: Math.floor(age) };
  };
  return {
    async lookup() {
      deadline = performance.now() + budget;
      if (!enabled || request.freshness !== "normal" || exact === "off" && semantic === "off") return {};
      try {
        let match = exact === "on" ? await validate(await optional(() => store.call("find", { request, kind: "exact" }))) : null;
        let kind = "exact";
        if (!match && semantic !== "off") {
          const vector = await embedding();
          if (vector) match = await validate(await optional(() => store.call("find", {
            request, kind: "semantic", embedding: vector, similarity: policy.memo_similarity ?? 0.92,
          })));
          kind = "semantic";
        }
        if (!match) return {};
        const memo = { kind, similarity: match.similarity, ...(kind === "semantic" ? { matched_query: match.record.query } : {}), age_seconds: match.age_seconds };
        if (kind === "semantic" && semantic === "observe") {
          const { kind: _kind, ...candidate } = memo;
          return { candidate };
        }
        await optional(() => store.call("hit", { id: match.record.id }));
        return { bundle: { ...structuredClone(match.record.bundle), query: request.query, path: "memo", providers_used: [],
          usage, served_at: nowIso(), elapsed_ms: Math.round(performance.now() - started), memo } };
      } catch { return {}; }
    },
    async write(bundle, failed) {
      deadline = Math.min(performance.now() + budget, options.memoWriteDeadlineAt ?? Infinity);
      if (deadline <= performance.now()) return;
      if (!enabled || failed || exact === "off" && semantic === "off" || !["ok", "partial"].includes(bundle.status) || !bundle.excerpts?.length) return;
      try {
        const saved = structuredClone(bundle);
        for (const name of ["usage", "served_at", "memo"]) delete saved[name];
        if (saved.index_diagnostics?.memo_candidate) delete saved.index_diagnostics.memo_candidate;
        if (new TextEncoder().encode(JSON.stringify(saved)).byteLength > MEMO_BUNDLE_BYTES) return;
        const citations = [...new Map([...saved.excerpts, ...(saved.related_evidence || [])].map(item => [item.artifact_id,
          { artifact_id: item.artifact_id, content_hash: item.content_hash, expires_at: item.expires_at }])).values()];
        // Memo backing follows the same live and published eligibility rules as retrieval.
        if (!(await optional(() => authority.call("memos.validate", { citations, policy_revision: policy.revision }))).valid) return;
        const vector = semantic !== "off" ? await embedding() : null;
        const key = memoKey(request);
        const queryNorm = memoQueryNorm(request.query);
        const time = nowIso();
        const record = { id: await digest(JSON.stringify([key, queryNorm, request.mode, bundle.token_count])), created_at: time,
          last_hit_at: time, hits: 0, key, query: request.query, query_norm: queryNorm, mode: request.mode,
          token_budget: request.token_budget, embedding: vector, bundle: saved, citations };
        const write = optional(() => store.call("put", { record })).catch(() => {});
        if (options.waitUntil) options.waitUntil(write);
        else await write;
      } catch { /* Memo storage is optional; verified retrieval remains usable. */ }
    },
  };
}
