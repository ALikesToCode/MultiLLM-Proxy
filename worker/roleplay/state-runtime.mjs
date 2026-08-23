import {
  loadRoleplayState,
  saveRoleplayState,
} from "./session-storage.mjs";

const MAX_ALARM_REFRESH_INTERVAL_MS = 86_400_000;
const MIN_ALARM_REFRESH_INTERVAL_MS = 60_000;

function alarmRefreshInterval(ttlMs) {
  return Math.max(
    MIN_ALARM_REFRESH_INTERVAL_MS,
    Math.min(MAX_ALARM_REFRESH_INTERVAL_MS, Math.floor(ttlMs / 2)),
  );
}

export function createRoleplayStateRepository(storage) {
  let cachedState = null;
  let persistedState = null;
  let pendingLoad = null;

  return {
    get loaded() {
      return cachedState !== null;
    },

    async load() {
      if (cachedState) {
        return cachedState;
      }
      if (!pendingLoad) {
        pendingLoad = loadRoleplayState(storage).then((state) => {
          cachedState = state;
          persistedState = state;
          return state;
        });
      }
      try {
        return await pendingLoad;
      } finally {
        pendingLoad = null;
      }
    },

    async save(state) {
      if (state === persistedState) {
        cachedState = state;
        return state;
      }
      await saveRoleplayState(storage, state, persistedState);
      cachedState = state;
      persistedState = state;
      return state;
    },

    clear() {
      cachedState = null;
      persistedState = null;
      pendingLoad = null;
    },
  };
}

export function createSessionAlarmRefresher(ctx, sessionTtlSeconds) {
  const ttlMs = sessionTtlSeconds * 1_000;
  const refreshIntervalMs = alarmRefreshInterval(ttlMs);
  let refreshAfter = 0;

  return () => {
    const now = Date.now();
    if (now < refreshAfter) {
      return;
    }
    refreshAfter = now + refreshIntervalMs;
    const update = Promise.resolve(
      ctx.storage.setAlarm(now + ttlMs),
    ).catch((error) => {
      refreshAfter = 0;
      const errorName =
        error instanceof Error && /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(error.name)
          ? error.name
          : "Error";
      console.error(
        JSON.stringify({ event: "roleplay_session_alarm_failed", errorName }),
      );
    });
    ctx.waitUntil(update);
  };
}

export function markRoleplayRequest(state, key, status) {
  if (!key) {
    return state;
  }
  const now = Date.now();
  const remaining = state.recentRequests
    .filter((entry) => entry?.key !== key)
    .filter((entry) => now - (entry?.at ?? 0) < 86_400_000)
    .slice(-31);
  return {
    ...state,
    recentRequests: [...remaining, { key, status, at: now }],
  };
}

export function existingRoleplayRequest(state, key) {
  return key
    ? state.recentRequests.find((entry) => entry?.key === key)
    : undefined;
}

export function effectiveRoleplayCharacter(state, parsed) {
  const supplied = Object.fromEntries(
    Object.entries(parsed.character).filter(([, value]) => Boolean(value)),
  );
  const profile = { ...state.profile, ...supplied };
  return {
    profile,
    parsed: { ...parsed, character: profile },
  };
}

export function recordRoleplayStateCache(state, hit) {
  return {
    ...state,
    stateCacheHits: (state.stateCacheHits ?? 0) + Number(hit),
    stateCacheMisses: (state.stateCacheMisses ?? 0) + Number(!hit),
  };
}

export function roleplayStateCacheMetrics(state) {
  const hits = state.stateCacheHits ?? 0;
  const misses = state.stateCacheMisses ?? 0;
  return {
    hits,
    misses,
    hit_rate: hits / Math.max(1, hits + misses),
  };
}
