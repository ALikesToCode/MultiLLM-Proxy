const BASE_BACKOFF_MS = 60_000;
const MAX_BACKOFF_MS = 15 * 60_000;

export function compactionBackoffActive(state, now = Date.now()) {
  return (state.compactionBackoffUntil ?? 0) > now;
}

export function recordCompactionSuccess(state) {
  if (
    !state.compactionFailures &&
    !state.compactionBackoffUntil
  ) {
    return state;
  }
  return {
    ...state,
    compactionFailures: 0,
    compactionBackoffUntil: 0,
  };
}

export function recordCompactionFailure(state, now = Date.now()) {
  const failures = Math.min(
    16,
    (state.compactionFailures ?? 0) + 1,
  );
  const backoffMs = Math.min(
    MAX_BACKOFF_MS,
    BASE_BACKOFF_MS * 2 ** Math.min(4, failures - 1),
  );
  return {
    ...state,
    compactionFailures: failures,
    compactionBackoffUntil: now + backoffMs,
  };
}
