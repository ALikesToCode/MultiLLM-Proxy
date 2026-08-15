import { fragmentChatMessages } from "./message-fragments.mjs";

const STATE_KEY = "roleplay-session";
const MESSAGES_KEY = "roleplay-messages";
const DIRECTIVES_KEY = "roleplay-directives";
const DIRECTIVE_SHARD_PREFIX = "roleplay-directives-shard:";
const DIRECTIVE_SHARD_FORMAT = "message-shards-v1";
const MAX_INLINE_DIRECTIVE_BYTES = 1_500_000;
const MAX_DIRECTIVE_FRAGMENT_BYTES = 240_000;
const MAX_DIRECTIVE_SHARDS = 64;

function encodedBytes(value) {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
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
    messages: Array.isArray(value.messages) ? value.messages : [],
    directives: Array.isArray(value.directives) ? value.directives : [],
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

export async function saveRoleplayState(storage, state) {
  const { directives, messages, ...core } = state;
  await storage.put({
    [STATE_KEY]: core,
    [MESSAGES_KEY]: messages,
    ...directiveStorageEntries(Array.isArray(directives) ? directives : []),
  });
}
