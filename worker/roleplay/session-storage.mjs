import { fragmentChatMessages } from "./message-fragments.mjs";

const STATE_KEY = "roleplay-session";
const MESSAGES_KEY = "roleplay-messages";
const DIRECTIVES_KEY = "roleplay-directives";
const DIRECTIVE_SHARD_PREFIX = "roleplay-directives-shard:";
const DIRECTIVE_SHARD_FORMAT = "message-shards-v1";
const MAX_INLINE_DIRECTIVE_BYTES = 1_500_000;
const MAX_DIRECTIVE_FRAGMENT_BYTES = 240_000;
const MAX_DIRECTIVE_SHARDS = 64;
const STORED_MESSAGE_ROLES = new Set([
  "system",
  "developer",
  "user",
  "assistant",
  "tool",
]);
const STORED_DIRECTIVE_ROLES = new Set(["system", "developer"]);

function encodedBytes(value) {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function normalizeStoredMessage(message, allowedRoles) {
  if (
    !message ||
    typeof message !== "object" ||
    Array.isArray(message) ||
    typeof message.role !== "string" ||
    typeof message.content !== "string" ||
    !message.content.trim()
  ) {
    return null;
  }
  const role = message.role.trim().toLowerCase();
  if (!allowedRoles.has(role)) {
    return null;
  }
  const normalized = { role, content: message.content };
  if (typeof message.name === "string" && message.name.trim()) {
    normalized.name = message.name.trim().slice(0, 100);
  }
  if (role === "tool") {
    if (
      typeof message.tool_call_id !== "string" ||
      !message.tool_call_id.trim()
    ) {
      return null;
    }
    normalized.tool_call_id = message.tool_call_id.trim().slice(0, 200);
  }
  return normalized;
}

function normalizeStoredMessages(value, allowedRoles) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((message) => normalizeStoredMessage(message, allowedRoles))
    .filter(Boolean);
}

export function createInitialRoleplayState() {
  return {
    version: 2,
    memory: null,
    compactionCheckpoint: null,
    messages: [],
    directives: [],
    profile: {},
    stats: {},
    activeCredentials: {},
    credentialUses: {},
    nanogptCredentialChecks: 0,
    turns: 0,
    compactions: 0,
    localCompactions: 0,
    inputTokensSaved: 0,
    stateCacheHits: 0,
    stateCacheMisses: 0,
    compactionFailures: 0,
    compactionBackoffUntil: 0,
    storageOverflow: false,
    recentRequests: [],
    updatedAt: 0,
  };
}

function normalizeState(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return createInitialRoleplayState();
  }
  return {
    ...createInitialRoleplayState(),
    ...value,
    version: 2,
    messages: normalizeStoredMessages(value.messages, STORED_MESSAGE_ROLES),
    directives: normalizeStoredMessages(
      value.directives,
      STORED_DIRECTIVE_ROLES,
    ),
    compactionCheckpoint:
      value.compactionCheckpoint &&
      typeof value.compactionCheckpoint === "object" &&
      !Array.isArray(value.compactionCheckpoint)
        ? value.compactionCheckpoint
        : null,
    profile:
      value.profile && typeof value.profile === "object" ? value.profile : {},
    stats: value.stats && typeof value.stats === "object" ? value.stats : {},
    activeCredentials:
      value.activeCredentials && typeof value.activeCredentials === "object"
        ? value.activeCredentials
        : {},
    credentialUses:
      value.credentialUses && typeof value.credentialUses === "object"
        ? value.credentialUses
        : {},
    recentRequests: Array.isArray(value.recentRequests)
      ? value.recentRequests
      : [],
  };
}

function isDirectiveManifest(value) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    value.format === DIRECTIVE_SHARD_FORMAT &&
    Number.isSafeInteger(value.shards) &&
    value.shards > 0 &&
    value.shards <= MAX_DIRECTIVE_SHARDS
  );
}

function directiveShardKey(index) {
  return `${DIRECTIVE_SHARD_PREFIX}${index}`;
}

async function loadDirectives(storage, stored) {
  if (Array.isArray(stored)) {
    return stored;
  }
  if (!isDirectiveManifest(stored)) {
    return [];
  }
  const shards = await Promise.all(
    Array.from({ length: stored.shards }, (_, index) =>
      storage.get(directiveShardKey(index)),
    ),
  );
  if (shards.some((shard) => !Array.isArray(shard))) {
    throw new Error("Roleplay directive storage is incomplete");
  }
  return shards.flat();
}

function packDirectiveShards(directives) {
  const fragments = fragmentChatMessages(
    directives,
    MAX_DIRECTIVE_FRAGMENT_BYTES,
  );
  const shards = [];
  let current = [];

  for (const fragment of fragments) {
    const candidate = [...current, fragment];
    if (current.length && encodedBytes(candidate) > MAX_INLINE_DIRECTIVE_BYTES) {
      shards.push(current);
      current = [fragment];
    } else {
      current = candidate;
    }
  }
  if (current.length) {
    shards.push(current);
  }
  if (
    shards.length > MAX_DIRECTIVE_SHARDS ||
    shards.some((shard) => encodedBytes(shard) > MAX_INLINE_DIRECTIVE_BYTES)
  ) {
    throw new Error("Roleplay directives exceed the durable storage limit");
  }
  return shards;
}

function directiveStorageEntries(directives) {
  if (encodedBytes(directives) <= MAX_INLINE_DIRECTIVE_BYTES) {
    return { [DIRECTIVES_KEY]: directives };
  }
  const shards = packDirectiveShards(directives);
  return {
    [DIRECTIVES_KEY]: {
      format: DIRECTIVE_SHARD_FORMAT,
      shards: shards.length,
    },
    ...Object.fromEntries(
      shards.map((shard, index) => [directiveShardKey(index), shard]),
    ),
  };
}

export async function loadRoleplayState(storage) {
  const [core, messages, storedDirectives] = await Promise.all([
    storage.get(STATE_KEY),
    storage.get(MESSAGES_KEY),
    storage.get(DIRECTIVES_KEY),
  ]);
  const directives = await loadDirectives(storage, storedDirectives);
  const hasStoredDirectives =
    Array.isArray(storedDirectives) ||
    isDirectiveManifest(storedDirectives);
  return normalizeState({
    ...(core && typeof core === "object" ? core : {}),
    messages: Array.isArray(messages) ? messages : [],
    directives: hasStoredDirectives
      ? directives
      : Array.isArray(core?.directives)
        ? core.directives
        : [],
  });
}

export async function saveRoleplayState(
  storage,
  state,
  previousState = null,
  metadata = {},
  retentionPolicy = null,
) {
  if (retentionPolicy?.enabled && retentionPolicy.mode === "zero") {
    await saveRetentionCounters(storage, state);
    return;
  }
  const { directives, messages, ...core } = state;
  const entries = { ...metadata, [STATE_KEY]: core };
  if (!previousState || previousState.messages !== messages) {
    entries[MESSAGES_KEY] = messages;
  }
  if (!previousState || previousState.directives !== directives) {
    Object.assign(
      entries,
      directiveStorageEntries(Array.isArray(directives) ? directives : []),
    );
  }
  await storage.put(entries);
}

const RETENTION_COUNTERS_KEY = "roleplay-retention-counters";
const RETENTION_COUNTER_FIELDS = ["turns", "compactions", "localCompactions", "inputTokensSaved",
  "stateCacheHits", "stateCacheMisses", "compactionFailures", "compactionBackoffUntil", "updatedAt",
  "nanogptCredentialChecks"];

function retentionCounters(state) {
  return Object.fromEntries(RETENTION_COUNTER_FIELDS.filter(key => Number.isFinite(state[key]) && state[key] >= 0)
    .map(key => [key, state[key]]));
}

const RETENTION_MODEL_FIELDS = ["attempts", "successes", "failures", "consecutiveFailures", "cooldownUntil",
  "ewmaTtfbMs", "ewmaTotalMs", "lastStatus", "lastUsedAt", "ewmaTokensPerSecond", "lastCompletionTokens",
  "lastGenerationMs", "semanticRefusals", "lastSemanticRefusalAt"];
const RETENTION_SAMPLE_FIELDS = ["ttfbSamplesMs", "totalSamplesMs", "tokensPerSecondSamples",
  "firstReasoningSamplesMs", "firstContentSamplesMs"];

async function retentionModelKey(key) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function retentionModelCounters(stats) {
  const counters = Object.fromEntries(RETENTION_MODEL_FIELDS.filter(key => Number.isFinite(stats?.[key]) && stats[key] >= 0)
    .map(key => [key, stats[key]]));
  for (const key of RETENTION_SAMPLE_FIELDS) {
    if (Array.isArray(stats?.[key])) counters[key] = stats[key].filter(value => Number.isFinite(value) && value >= 0).slice(-64);
  }
  return counters;
}

async function saveRetentionCounters(storage, state) {
  const counters = retentionCounters(state);
  counters.stats = Object.fromEntries(await Promise.all(Object.entries(state.stats ?? {}).map(async ([key, stats]) =>
    [await retentionModelKey(key), retentionModelCounters(stats)])));
  // Request identities are already hashed at the turn boundary. Ignore arbitrary metadata.
  counters.recentRequests = (state.recentRequests ?? []).filter(row => /^[a-f0-9]{64}$/.test(row.key)
    && Number.isFinite(row.at) && /^[a-z_]{1,64}$/.test(row.status))
    .map(({ key, at, status }) => ({ key, at, status })).slice(-32);
  await storage.put(RETENTION_COUNTERS_KEY, counters);
}

export function createRetentionStateRepository(storage, repository, policy, candidates = []) {
  if (!policy?.enabled || policy.mode !== "zero") return repository;
  return {
    loaded: false,
    async load() {
      const saved = await storage.get(RETENTION_COUNTERS_KEY) ?? {};
      const entries = await Promise.all(candidates.map(async candidate => {
        const prior = saved.stats?.[await retentionModelKey(candidate.key)];
        return prior ? [candidate.key, { provider: candidate.provider, model: candidate.model,
          family: candidate.family, ...retentionModelCounters(prior) }] : null;
      }));
      const stats = Object.fromEntries(entries.filter(Boolean));
      return { ...createInitialRoleplayState(), ...retentionCounters(saved),
        stats, recentRequests: Array.isArray(saved.recentRequests) ? saved.recentRequests : [] };
    },
    async save(state) { await saveRetentionCounters(storage, state); return state; },
  };
}
