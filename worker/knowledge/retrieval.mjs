import { fail, KnowledgeError, publicUrl } from "./contracts.mjs";
import { createArtifact, evidenceMatch, isProviderContext, normalizeSourceText, packEvidence, packProviderContext, selectPassage, validateChunk } from "./evidence.mjs";
import { KnowledgeCorpus } from "./corpus.mjs";
import { providerStatus, retrieve } from "./providers/index.mjs";
import { confirmSnapshot, metered } from "./operations.mjs";
import { cacheKey, readCache, writeCache } from "./cache.mjs";
import { retentionHours, sourceReviewed } from "./policy.mjs";

const safeCode = error => /^[a-z0-9_]{1,80}$/.test(error?.code ?? "") ? error.code : "upstream_unavailable";
// Economy asks one provider; smart and deep ask every eligible provider in parallel.
const MODE_PROVIDER_LIMITS = { economy: 1, smart: Infinity, deep: Infinity };
const OBSERVATIONS_PER_PROVIDER = { economy: 5, smart: 6, deep: 10 };
const MAX_RETAINED_SOURCES = { economy: 3, smart: 3, deep: 5 };
// Failed or refused sources do not fill a retention slot, so bound the paid attempts separately.
const MAX_LIVE_ATTEMPTS = { economy: 6, smart: 6, deep: 10 };
// Soft budgets inside the 24 s retrieval deadline: a slow provider or acquisition is
// reported as a gap, and the answer is built from everything that arrived in time.
const PROVIDER_BUDGET_MS = 14000;
const LIVE_BUDGET_MS = 19000;
const RETRIEVAL_DEADLINE_MS = 24000;
// Publication or expiry elsewhere can change the corpus while a query runs.
const MAX_REVALIDATIONS = 3;
const nowIso = () => new Date().toISOString();

function eligibleArtifact(artifact, snapshot, now) {
  const source = snapshot.sources.find(item => item.id === artifact?.source_id);
  if (!artifact || artifact.status === "expiring" || !source?.enabled || Date.parse(artifact.expires_at) <= now
    || !snapshot.policy.providers[artifact.provider]?.enabled || !snapshot.policy.providers[artifact.provider]?.retention_allowed) return false;
  try { publicUrl(artifact.canonical_url, snapshot.policy.allowed_hosts); }
  catch { return false; }
  return true;
}

function candidateProviders(env, request, policy) {
  const configured = new Set(providerStatus(env).filter(item => item.configured && policy.providers[item.id]?.enabled).map(item => item.id));
  const order = request.mode === "economy" ? ["exa", "context7", "mintlify", "deepwiki"]
    : ["context7", "exa", "mintlify", "deepwiki"];
  return order.filter(id => configured.has(id) && (id !== "deepwiki" || request.repository)
    && (id !== "context7" || request.product || request.repository)).slice(0, MODE_PROVIDER_LIMITS[request.mode]);
}

// Acquisition counts toward the mode's provider limit: reuse a selected provider,
// or add one only while the mode has room. Otherwise discoveries stay unacquired.
function acquisitionProviderFor(env, request, policy, providers) {
  const room = providers.length < MODE_PROVIDER_LIMITS[request.mode];
  return ["firecrawl", "exa"].find(id => providerStatus(env).some(item => item.id === id && item.configured)
    && policy.providers[id]?.enabled && (providers.includes(id) || room));
}

function budgetSignal(state, milliseconds) {
  return AbortSignal.any([state.signal, AbortSignal.timeout(Math.max(0, Math.round(state.started + milliseconds - performance.now())))]);
}

function checkAbort(signal) {
  if (signal.aborted) fail("retrieval_deadline", "The retrieval deadline was reached.", 504);
}

async function untilDeadline(callback, signal) {
  checkAbort(signal);
  let listener;
  const cancelled = new Promise((_, reject) => {
    listener = () => reject(new KnowledgeError("retrieval_deadline", "The retrieval deadline was reached.", 504));
    signal.addEventListener("abort", listener, { once: true });
  });
  try { return await Promise.race([callback(), cancelled]); }
  finally { signal.removeEventListener("abort", listener); }
}

const reviewOf = (source, policy) => sourceReviewed(source, policy) ? "reviewed" : "unreviewed";

function originIsFresh(artifact) {
  const checked = Date.parse(artifact.checked_at);
  return Number.isFinite(checked) && Date.now() - checked <= 3600000;
}

// A failure makes the bundle retryable: it is reported as a gap and never cached.
function failed(state, code, message) {
  state.failed = true;
  state.gaps.push({ code, message });
}

function providerWarnings(state, provider, batch) {
  for (const code of batch.warnings ?? []) {
    if (typeof code === "string" && /^[a-z0-9_]{1,80}$/.test(code)) {
      state.gaps.push({ code, message: `${provider} reported a source coverage or verification limitation.` });
    }
  }
}

// Reads each distinct key once, concurrently, and settles results in input order.
// Callers walk them in order and stop at the first rejection, keeping the outcome
// of a sequential loop without one catalogue or snapshot round trip per row.
function settledInOrder(items, keyOf, read) {
  const reads = new Map();
  return Promise.allSettled(items.map(item => {
    const key = keyOf(item);
    if (!reads.has(key)) reads.set(key, read(item));
    return reads.get(key);
  }));
}

async function indexedEvidence(state) {
  const { authority, corpus, request, snapshot, invoke } = state;
  if (!snapshot.sources.some(source => source.enabled && source.current_artifact) || !snapshot.policy.providers.ai_search.enabled) return;
  state.attempts += 1;
  try {
    const rows = await invoke("ai_search", "query", () => corpus.search(request));
    state.successes += 1;
    state.paths.add("index");
    checkAbort(state.signal);
    const diagnostics = { hits: rows.length, admitted: 0, skipped: {} };
    state.indexDiagnostics = diagnostics;
    const skip = reason => { diagnostics.skipped[reason] = (diagnostics.skipped[reason] ?? 0) + 1; };
    const resolved = await settledInOrder(rows, row => row.index_key, async row => {
      const artifact = await authority.call("artifact.for_key", { key: row.index_key });
      if (!artifact) return { skipped: "unknown_revision" };
      if (!eligibleArtifact(artifact, snapshot, Date.now())) return { skipped: "ineligible" };
      if (artifact.status !== "published") return { skipped: "unpublished" };
      // Each version has its own source record, so older revisions of this source are obsolete.
      const source = snapshot.sources.find(item => item.id === artifact.source_id);
      if (source.current_artifact !== artifact.id) return { skipped: "superseded" };
      return { artifact, text: await untilDeadline(() => corpus.getSnapshot(artifact), state.signal) };
    });
    for (const [index, row] of rows.entries()) {
      checkAbort(state.signal);
      if (resolved[index].status === "rejected") throw resolved[index].reason;
      const { artifact, text, skipped } = resolved[index].value;
      if (skipped) { skip(skipped); continue; }
      const excerpt = text && validateChunk(artifact, text, row.text);
      if (!excerpt) {
        skip("span_mismatch");
        failed(state, "invalid_source_span", "An index candidate could not be matched to its retained source.");
        continue;
      }
      if (request.freshness === "fresh" && !originIsFresh(artifact)) { skip("not_fresh"); continue; }
      diagnostics.admitted += 1;
      const source = snapshot.sources.find(item => item.id === artifact.source_id);
      state.candidates.push({ ...excerpt, target_match: evidenceMatch(artifact, request), score: row.score,
        source_review: reviewOf(source, snapshot.policy) });
    }
  } catch (error) {
    failed(state, safeCode(error), "Indexed retrieval could not complete.");
  }
}

async function storeObservation(state, observation, sequence) {
  const { authority, corpus, request, snapshot } = state;
  checkAbort(state.signal);
  const url = publicUrl(observation.url, snapshot.policy.allowed_hosts);
  const text = normalizeSourceText(observation.text);
  const source = await authority.call("source.discover", { url, product: request.product || new URL(url).hostname,
    version: request.version, provider: observation.provider, title: observation.title?.slice(0, 200) || new URL(url).hostname });
  if (!source.enabled) return false;
  const candidate = await createArtifact({ ...source, retention_hours: retentionHours(source, snapshot.policy),
    origin_checked: observation.freshness === "live" }, text, observation.provider);
  // Record the immutable manifest before R2 so interrupted writes remain discoverable
  // for retention cleanup. An unreadable snapshot can never become an excerpt.
  await authority.call("artifact.save", { artifact: candidate });
  // Snapshots are content-addressed. Reuse retained bytes rather than spending an
  // allowance unit on a write that would change nothing.
  const retained = await untilDeadline(() => corpus.getSnapshot(candidate), state.signal).catch(() => null);
  const written = retained === text ? { key: candidate.snapshot_key, created: false }
    : await state.invoke("ai_search", `snapshot-${sequence}`, () => corpus.putSnapshot(candidate, text));
  checkAbort(state.signal);
  const artifact = await confirmSnapshot(authority, corpus, candidate, written);
  const excerpt = validateChunk(artifact, text, selectPassage(text, request.query));
  if (excerpt && (request.freshness !== "fresh" || originIsFresh(artifact))) {
    state.candidates.push({ ...excerpt, target_match: evidenceMatch(artifact, request), score: 0.75,
      source_review: reviewOf(source, snapshot.policy) });
  } else if (request.freshness === "fresh") {
    state.gaps.push({ code: "freshness_unverified", message: "The acquired source did not establish a recent origin check." });
  }
  state.paths.add("live");
  if (source.current_artifact !== artifact.id) state.sourcesToIndex.set(source.id, artifact.id);
  return true;
}

async function liveEvidence(state, env, retrieveFn) {
  const { request, snapshot, signal } = state;
  const providers = candidateProviders(env, request, snapshot.policy);
  const intent = { ...request, allowed_hosts: snapshot.policy.allowed_hosts };
  const providerSignal = budgetSignal(state, state.budgets.provider);
  const batches = await Promise.all(providers.map(async provider => {
    state.attempts += 1;
    try {
      const batch = await untilDeadline(() => retrieveFn(provider, intent, { env, signal: providerSignal, authority: state.authority,
        invoke: (id, suffix, callback) => state.invoke(id, `${provider}-${suffix}`, callback) }), providerSignal);
      state.successes += 1;
      state.providersUsed.add(provider);
      providerWarnings(state, provider, batch);
      state.providerContext.push(...batch.observations.filter(isProviderContext));
      return batch.observations.filter(item => !isProviderContext(item)).slice(0, OBSERVATIONS_PER_PROVIDER[request.mode]);
    } catch (error) {
      if (providerSignal.aborted && !signal.aborted) failed(state, "provider_timeout", `${provider} did not answer within the retrieval budget.`);
      else failed(state, safeCode(error), `${provider} could not supply evidence.`);
      return [];
    }
  }));
  const seen = new Set();
  let stored = 0;
  let attempts = 0;
  const acquisitionProvider = acquisitionProviderFor(env, request, snapshot.policy, providers);
  const observations = batches.flat().sort((a, b) => Number(b.kind === "source_excerpt") - Number(a.kind === "source_excerpt"));
  const liveSignal = budgetSignal(state, state.budgets.live);
  for (const observation of observations) {
    if (stored >= MAX_RETAINED_SOURCES[request.mode] || attempts >= MAX_LIVE_ATTEMPTS[request.mode]) break;
    if (liveSignal.aborted) {
      if (!signal.aborted) state.gaps.push({ code: "acquisition_budget_reached", message: "Further discovered sources were not acquired so the answer could return in time." });
      break;
    }
    let url;
    try { url = publicUrl(observation.url, snapshot.policy.allowed_hosts); }
    catch { continue; }
    if (seen.has(url)) continue;
    state.discoveries.push({ url, title: (observation.title || url).slice(0, 200), provider: observation.provider, kind: observation.kind });
    const excerpt = observation.kind === "source_excerpt";
    if (!excerpt && !acquisitionProvider) continue;
    // Every attempt has its own operation IDs; only a retained source fills a slot.
    const sequence = attempts++;
    try {
      let original = observation;
      if (!excerpt) {
        state.attempts += 1;
        const batch = await untilDeadline(() => retrieveFn(acquisitionProvider, { ...intent, source_url: url }, { env, signal: liveSignal, authority: state.authority,
          invoke: (id, suffix, callback) => state.invoke(id, `acquire-${sequence}-${suffix}`, callback) }), liveSignal);
        state.successes += 1;
        state.providersUsed.add(acquisitionProvider);
        providerWarnings(state, acquisitionProvider, batch);
        original = batch.observations.find(item => item.kind === "source_excerpt" && item.url === url);
      }
      if (original && await storeObservation(state, original, sequence)) {
        seen.add(url);
        stored += 1;
      }
    } catch (error) {
      if (liveSignal.aborted && !signal.aborted) {
        state.gaps.push({ code: "acquisition_budget_reached", message: "Further discovered sources were not acquired so the answer could return in time." });
        break;
      }
      failed(state, safeCode(error), "A discovered source could not be acquired and retained.");
    }
  }
  if (!providers.length) state.gaps.push({ code: "no_eligible_provider", message: "Configure a provider and its allowance to retrieve missing evidence." });
}

async function revalidateCandidates(state, snapshot, candidates) {
  const result = [];
  const artifacts = await settledInOrder(candidates, candidate => candidate.artifact_id,
    candidate => state.authority.call("artifact.get", { id: candidate.artifact_id }));
  for (const [index, candidate] of candidates.entries()) {
    if (artifacts[index].status === "rejected") throw artifacts[index].reason;
    const artifact = artifacts[index].value;
    if (!eligibleArtifact(artifact, snapshot, Date.now())) continue;
    if (state.request.freshness === "fresh" && !originIsFresh(artifact)) continue;
    const source = snapshot.sources.find(item => item.id === artifact.source_id);
    if (artifact.status === "published" && source.current_artifact !== artifact.id) continue;
    result.push(candidate);
  }
  return result;
}

// A corpus change since the key was computed makes the entry stale, not the query invalid:
// the query continues as a miss and is validated against the corpus it finishes with.
async function cacheHit(cache, key, state) {
  const bundle = await untilDeadline(() => readCache(cache, key), state.signal);
  if (!bundle) return null;
  const latest = await state.authority.call("catalogue.state");
  assertPolicy(state.snapshot, latest);
  if (latest.generation !== state.snapshot.generation) return null;
  const candidates = [...bundle.excerpts, ...(bundle.related_evidence || [])];
  const valid = await revalidateCandidates(state, latest, candidates);
  const confirmed = await state.authority.call("catalogue.state");
  assertPolicy(state.snapshot, confirmed);
  if (confirmed.generation !== latest.generation || valid.length !== candidates.length) return null;
  return { ...bundle, path: "cache", providers_used: [], evidence_providers: [...new Set(valid.map(item => item.provider))],
    usage: [], elapsed_ms: Math.round(performance.now() - state.started), served_at: nowIso() };
}

function assertPolicy(previous, latest) {
  if (!latest.policy.enabled || latest.policy.revision !== previous.policy.revision) {
    fail("policy_changed", "Knowledge policy changed during retrieval. Submit a new query using the current policy.", 409);
  }
}

// Revalidate against a catalogue state that stayed unchanged for the whole check, instead
// of failing a query whose providers were already paid because unrelated work published.
async function currentCandidates(state) {
  for (let attempt = 1; ; attempt += 1) {
    const latest = await state.authority.call("catalogue.state");
    assertPolicy(state.snapshot, latest);
    const candidates = await revalidateCandidates(state, latest, state.candidates);
    const confirmed = await state.authority.call("catalogue.state");
    assertPolicy(state.snapshot, confirmed);
    if (confirmed.generation === latest.generation) return { latest, candidates };
    if (attempt >= MAX_REVALIDATIONS) {
      fail("corpus_changed", "The corpus kept changing during retrieval. Submit the query again.", 409);
    }
  }
}

async function runRetrieval(env, authority, principal, request, options, signal, started, meterAuthority) {
  const snapshot = await authority.call("catalogue.state");
  if (!snapshot.policy.enabled) fail("knowledge_disabled", "Enable Knowledge and configure provider allowances before querying.", 503);
  if (!env.KNOWLEDGE_SNAPSHOTS || !env.KNOWLEDGE_INDEX) fail("storage_unavailable", "Configure the Knowledge snapshot and index bindings.", 503);
  const state = { authority, corpus: options.corpus || new KnowledgeCorpus(env), request, snapshot, signal,
    started, candidates: [], discoveries: [], gaps: [], usage: [], paths: new Set(),
    providersUsed: new Set(), sourcesToIndex: new Map(), providerContext: [], attempts: 0, successes: 0, failed: false,
    budgets: { provider: options.providerBudgetMs ?? PROVIDER_BUDGET_MS, live: options.liveBudgetMs ?? LIVE_BUDGET_MS } };
  const requestId = crypto.randomUUID();
  state.invoke = async (provider, suffix, callback) => {
    checkAbort(signal);
    let confirmed = false;
    try {
      const result = await untilDeadline(() => metered(meterAuthority,
        { provider, operation_id: `${requestId}:${suffix}`, background: false },
        () => untilDeadline(callback, signal)), signal);
      confirmed = true;
      return result;
    } finally {
      state.usage.push({ provider, operation_id: `${requestId}:${suffix}`, bound_units: snapshot.policy.providers[provider]?.units_per_call ?? 0,
        outcome: confirmed ? "completed" : "unconfirmed", measurement: "configured_operation_bound" });
    }
  };
  const cache = options.cache ?? globalThis.caches?.default;
  const key = await cacheKey(principal, request, snapshot);
  if (request.freshness === "normal" && snapshot.policy.cache_ttl_seconds > 0) {
    const cached = await cacheHit(cache, key, state);
    if (cached) return cached;
  }
  await indexedEvidence(state);
  if (!state.candidates.some(item => item.target_match !== "unverified") || request.freshness === "fresh" || request.mode === "deep") {
    await liveEvidence(state, env, options.retrieve || retrieve);
  }
  if (!state.successes && state.attempts) {
    if (state.gaps.some(gap => gap.code === "provider_keys_exhausted")) {
      fail("provider_keys_exhausted", "A Knowledge provider has no available API keys. Add capacity or wait for its reset window.", 429);
    }
    const limit = state.gaps.some(gap => gap.code === "allowance_exhausted");
    fail(limit ? "allowance_exhausted" : "retrieval_failed", limit ? "The configured Knowledge allowance is exhausted."
      : "All attempted retrieval providers failed; no successful empty result was recorded.", limit ? 429 : 502);
  }
  const { latest, candidates } = await currentCandidates(state);
  state.candidates = candidates;
  // Verified excerpts keep most of the budget; provider context gets up to 40% of it,
  // or all of it when no source excerpt was found.
  const providerContext = packProviderContext(state.providerContext,
    Math.floor(request.token_budget * (state.candidates.length ? 0.4 : 1)));
  const packed = packEvidence(state.candidates, { ...request, token_budget: request.token_budget - providerContext.token_count });
  if (!packed.excerpts.length) state.gaps.push({ code: request.version ? "version_not_verified" : "insufficient_evidence",
    message: request.version ? `No retained source verifies the requested version ${request.version}. Related versions are separated.`
      : "No matching source excerpts were available." });
  const bundle = { ...packed, token_count: packed.token_count + providerContext.token_count, provider_context: providerContext.items,
    status: !packed.excerpts.length ? (providerContext.items.length ? "partial" : "insufficient_evidence") : state.gaps.length ? "partial" : "ok",
    query: request.query, requested_version: request.version || null, discoveries: state.discoveries,
    gaps: state.gaps, providers_used: [...state.providersUsed], evidence_providers: [...new Set(state.candidates.map(item => item.provider))],
    path: state.paths.size > 1 ? "mixed" : [...state.paths][0] || "live", elapsed_ms: Math.round(performance.now() - state.started),
    index_diagnostics: state.indexDiagnostics ?? null,
    usage: state.usage, served_at: nowIso(), freshness: { requested: request.freshness,
      source_checks: [...new Set(state.candidates.map(item => item.checked_at))] } };
  if (options.schedule && latest.policy.providers.ai_search.background_limit > 0) {
    await Promise.all([...state.sourcesToIndex].map(([sourceId, artifactId]) =>
      untilDeadline(() => options.schedule(sourceId, signal, artifactId), signal).catch(() => {
        failed(state, "indexing_not_scheduled", "Live evidence is retained; indexing could not be scheduled.");
      })));
    if (bundle.status === "ok" && state.gaps.length) bundle.status = "partial";
  }
  // Cache only a finished bundle without failures: a failed provider, read or schedule
  // is not cached, so the next request retries. Provider coverage notes are stable for
  // the same query and corpus, so they do not prevent caching. Publication/policy races
  // never create cache entries for an obsolete generation.
  if (latest.generation === snapshot.generation && !state.failed) {
    await untilDeadline(() => writeCache(cache, key, bundle, snapshot.policy.cache_ttl_seconds), signal);
  }
  checkAbort(signal);
  return bundle;
}

export async function retrieveKnowledge(env, authority, principal, request, options = {}) {
  const started = performance.now();
  const timeout = AbortSignal.timeout(RETRIEVAL_DEADLINE_MS);
  const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;
  const bounded = { call: (operation, payload) => untilDeadline(() => authority.call(operation, payload), signal) };
  // The deadline includes catalogue, cache, snapshots and scheduling, not only HTTP.
  // Already admitted operations retain their durable pending/unknown reservations.
  return untilDeadline(() => runRetrieval(env, bounded, principal, request, options, signal, started, authority), signal);
}
