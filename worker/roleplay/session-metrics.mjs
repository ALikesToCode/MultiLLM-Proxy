import { estimateTokens } from "./memory.mjs";
import { roleplayStateCacheMetrics } from "./state-runtime.mjs";
import { modelLatencyPercentiles } from "./transport.mjs";

function modelMetrics(stats) {
  return Object.fromEntries(
    Object.entries(stats).map(([key, value]) => [
      key,
      {
        provider: value.provider,
        model: value.model,
        family: value.family,
        attempts: value.attempts,
        successes: value.successes,
        failures: value.failures,
        consecutive_failures: value.consecutiveFailures,
        ewma_ttfb_ms: value.ewmaTtfbMs,
        ewma_total_ms: value.ewmaTotalMs,
        latency: modelLatencyPercentiles(value),
        cooldown_until: value.cooldownUntil,
        last_status: value.lastStatus,
        last_used_at: value.lastUsedAt,
      },
    ]),
  );
}

export function buildRoleplaySessionMetrics(state, runtime = {}) {
  return {
    turns: state.turns,
    compactions: state.compactions,
    local_compactions: state.localCompactions,
    compaction_failures: state.compactionFailures,
    compaction_backoff_until: state.compactionBackoffUntil || null,
    storage_overflow: state.storageOverflow,
    stored_messages: state.messages.length,
    protected_directives: state.directives.length,
    estimated_protected_directive_tokens: estimateTokens(state.directives),
    compacted_prefix_messages:
      state.compactionCheckpoint?.messageCount ?? 0,
    estimated_stored_tokens: estimateTokens({
      memory: state.memory,
      messages: state.messages,
    }),
    estimated_input_tokens_saved: state.inputTokensSaved ?? 0,
    state_cache: roleplayStateCacheMetrics(state),
    pending_turns: runtime.pendingTurns ?? 0,
    nanogpt_credential_checks: state.nanogptCredentialChecks ?? 0,
    models: modelMetrics(state.stats),
    updated_at: state.updatedAt || null,
  };
}
