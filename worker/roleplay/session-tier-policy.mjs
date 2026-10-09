import { RoleplayTurnError } from "./turn-runtime.mjs";

const LANES = new Set(["main", "delegation", "aux"]);
const MAX_TOOLS = 128;
let warned = false;
export class SessionTierError extends RoleplayTurnError {}
const error = (code, message, status = 503) => new SessionTierError(code, status, message);

export function sessionTierSettings(env = {}) {
  const mode = String(env.SESSION_TIER_MODE || "off").trim() || "off";
  const raw = String(env.SESSION_TIER_TTL_SECONDS || "1800").trim() || "1800";
  const ttlSeconds = Number(raw);
  if (!["off", "sticky"].includes(mode) || !/^\d+$/.test(raw) || !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 86400) {
    if (!warned) { warned = true; console.warn("Invalid session tier settings; session tiers disabled"); }
    return { enabled: false, ttlSeconds: 1800 };
  }
  return { enabled: mode === "sticky", ttlSeconds };
}

export function parseSessionTier(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join(",") !== "approved_model,approved_tier,lane" ||
      !LANES.has(value.lane) || !Number.isInteger(value.approved_tier) || value.approved_tier < 0 || value.approved_tier > 100 ||
      typeof value.approved_model !== "string" || value.approved_model.length > 256 ||
      !/^[a-z][a-z0-9-]{0,31}:[A-Za-z0-9][A-Za-z0-9._:/+@-]*$/.test(value.approved_model)) {
    throw error("invalid_session_tier", "Session tier requires a lane and explicit model/tier approval", 400);
  }
  return { ...value };
}

async function digest(...parts) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(parts)));
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, "0")).join("");
}
const modelId = c => `${c.provider}:${c.model}`;
async function toolHash(id) {
  if (typeof id !== "string" || !id.trim() || id.length > 200) throw error("invalid_session_tier", "Invalid tool call marker", 400);
  return digest("tool", id);
}
async function pendingAfterMessages(prior, messages) {
  if (!Array.isArray(messages) || messages.length > 256) throw error("invalid_session_tier", "Invalid session messages", 400);
  const pending = new Set(prior);
  for (const message of messages) {
    if (!message || typeof message !== "object") throw error("invalid_session_tier", "Invalid session message", 400);
    if (message.role === "assistant") {
      const calls = message.tool_calls || [];
      if (!Array.isArray(calls) || calls.length > MAX_TOOLS) throw error("session_tier_tool_limit", "Invalid tool call markers", 400);
      for (const call of calls) pending.add(await toolHash(call?.id));
    } else if (message.role === "tool") pending.delete(await toolHash(message.tool_call_id));
    if (pending.size > MAX_TOOLS) throw error("session_tier_tool_limit", "Too many outstanding tool calls", 400);
  }
  return [...pending].sort();
}

export async function sessionTierRevision(candidates) {
  // Route metadata only: never fingerprint or retain the configured credentials.
  return digest("roleplay-policy", candidates.map(c => [c.provider, c.model, c.credentialId,
    c.subscriptionOnly, c.billingMode, c.familyRank, c.modelRank, c.providerRank,
    c.priorityRank, c.contextWindow, c.maxOutputTokens]));
}

export class SessionTierPolicy {
  constructor(storage, settings, clock = () => Date.now() / 1000) {
    this.storage = storage;
    this.settings = settings;
    this.clock = clock;
    this.tail = Promise.resolve();
  }

  async update(key, operation) {
    const previous = this.tail;
    let release;
    this.tail = new Promise(resolve => { release = resolve; });
    await previous;
    try {
      const row = await this.storage.get(key);
      const [next, result] = await operation(row);
      if (next) await this.storage.put(key, next);
      else if (row) await this.storage.delete(key);
      return result;
    } catch (e) {
      if (e instanceof RoleplayTurnError) throw e;
      throw error("session_tier_storage_unavailable", "Session tier storage is unavailable");
    } finally { release(); }
  }

  async begin(raw, candidates, messages, revision, { explicit = false, unavailable = () => false } = {}) {
    if (!this.settings.enabled || !raw || explicit) return null;
    const requested = parseSessionTier(raw);
    // This repository belongs to an authenticated, session-scoped Durable Object.
    const key = `session-tier:${await digest("lane", requested.lane)}`;
    const policyRevision = await digest("revision", revision);
    return this.update(key, async row => {
      if (row && row.expires_at <= this.clock()) row = null;
      if (row?.lease) throw error("session_tier_busy", "A session lane already has an unresolved request", 409);
      if (row && row.policy_revision !== policyRevision) row = null;
      const pending = await pendingAfterMessages(row?.pending_tools ?? [], messages);
      const safe = !pending.length && messages.at(-1)?.role === "user" && row?.safe_turn;
      const change = !row || (safe && (row.approved_model !== requested.approved_model || row.tier !== requested.approved_tier));
      const approved = change ? requested.approved_model : row.approved_model;
      const tier = change ? requested.approved_tier : row.tier;
      const nativeModel = approved.slice(approved.indexOf(":") + 1);
      // Roleplay has no reviewed numeric quality tiers. The approval is a label;
      // fallback is restricted to the identical native model on eligible providers.
      const allowed = candidates.filter(c => c.model === nativeModel && !unavailable(c));
      if (change && !allowed.some(c => modelId(c) === approved)) throw error("session_tier_ineligible", "Approved model is not eligible");
      if (!allowed.length) return [null, error("session_tier_ineligible", "No eligible route remains for approved model")];
      const next = { lane: requested.lane, tier, approved_model: approved,
        actual_model: change ? approved : row.actual_model, policy_revision: policyRevision,
        expires_at: this.clock() + this.settings.ttlSeconds, safe_turn: false,
        pending_tools: pending, lease: crypto.randomUUID() };
      const ordered = [...allowed].sort((a, b) => Number(modelId(a) !== next.actual_model) - Number(modelId(b) !== next.actual_model));
      return [next, new SessionTierTurn(this, key, next, ordered)];
    }).then(result => { if (result instanceof Error) throw result; return result; });
  }
}

class SessionTierTurn {
  constructor(policy, key, row, candidates) {
    this.policy = policy; this.key = key; this.row = row; this.candidates = candidates;
    this.observedTools = [];
    this.observationInvalid = false;
  }

  select(candidates) {
    const allowed = new Set(this.candidates.map(modelId));
    return candidates.filter(c => allowed.has(modelId(c))).sort((a, b) =>
      Number(modelId(a) !== this.row.actual_model) - Number(modelId(b) !== this.row.actual_model));
  }

  observe(response) {
    if (!response.body || !response.headers.get("content-type")?.includes("text/event-stream")) return response;
    const decoder = new TextDecoder();
    let buffer = "";
    const ids = new Map();
    const transform = new TransformStream({ transform: (chunk, controller) => {
      controller.enqueue(chunk);
      if (this.observationInvalid) return;
      buffer += decoder.decode(chunk, { stream: true });
      if (buffer.length > 65536) { this.observationInvalid = true; buffer = ""; return; }
      const lines = buffer.split(/\r?\n/); buffer = lines.pop();
      for (const line of lines) {
        if (!line.startsWith("data:") || line.slice(5).trim() === "[DONE]") continue;
        try {
          const frame = JSON.parse(line.slice(5));
          for (const call of frame.choices?.[0]?.delta?.tool_calls ?? []) {
            if (!Number.isInteger(call.index) || call.index < 0 || call.index >= MAX_TOOLS) { this.observationInvalid = true; break; }
            if (typeof call.id === "string") ids.set(call.index, (ids.get(call.index) ?? "") + call.id);
            if ((ids.get(call.index)?.length ?? 0) > 200) this.observationInvalid = true;
            this.observedTools = [...ids.values()].map(id => ({ id }));
          }
        } catch { this.observationInvalid = true; }
      }
    }, flush: () => { this.observedTools = [...ids.values()].map(id => ({ id })); buffer = ""; ids.clear(); } });
    return new Response(response.body.pipeThrough(transform), { status: response.status, statusText: response.statusText, headers: response.headers });
  }

  async finish(candidate, { success = false, toolCalls = this.observedTools, finishReason = "", credentialFailed = false } = {}) {
    return this.policy.update(this.key, async current => {
      if (!current || current.lease !== this.row.lease) return [current, null];
      if (credentialFailed) return [null, null];
      if (candidate) {
        if (!this.candidates.some(c => modelId(c) === modelId(candidate))) throw error("session_tier_ineligible", "Actual route is outside approved model");
        current.actual_model = modelId(candidate);
      }
      if (!Array.isArray(toolCalls) || toolCalls.length > MAX_TOOLS) throw error("session_tier_tool_limit", "Too many tool calls");
      const pending = new Set(current.pending_tools);
      for (const call of toolCalls) pending.add(await toolHash(call?.id));
      if (this.observationInvalid || (finishReason === "tool_calls" && !toolCalls.length)) {
        pending.add(await digest("unobserved-tool-state"));
      }
      if (pending.size > MAX_TOOLS) throw error("session_tier_tool_limit", "Too many outstanding tool calls");
      current.pending_tools = [...pending].sort();
      current.safe_turn = Boolean(candidate && success && !this.observationInvalid && (finishReason !== "tool_calls" || toolCalls.length));
      current.lease = "";
      return [current, null];
    });
  }
}

export async function beginRoleplaySessionTier(policy, parsed, payload, candidates, stats, configured) {
  const raw = parsed.routing.session_tier;
  if (!raw || !policy.settings.enabled || parsed.routing.mode === "pinned" || parsed.routing.model) return null;
  return policy.begin(raw, candidates, payload.messages ?? parsed.messages,
    await sessionTierRevision(configured), { unavailable: c => stats[c.key]?.cooldownUntil > Date.now() });
}
