const MAX_THROUGHPUT_SAMPLES = 64;
const EWMA_ALPHA = 0.25;

function positiveNumber(value) {
  return Number.isFinite(value) && value > 0 ? value : null;
}

function rounded(value) {
  return Number.isFinite(value) ? Math.round(value * 100) / 100 : null;
}

function percentile(values, percentileValue) {
  if (!Array.isArray(values) || !values.length) {
    return null;
  }
  const ordered = [...values].sort((left, right) => left - right);
  const index = Math.max(
    0,
    Math.ceil((percentileValue / 100) * ordered.length) - 1,
  );
  return rounded(ordered[index]);
}

export function recordThroughputObservation(
  stats,
  { completionTokens, generationMs, firstReasoningMs, firstContentMs, headerMs = 0, upstreamCallCount = 1 } = {},
) {
  // A multi-leg turn can change models; its aggregate is not one model's TPS.
  if (upstreamCallCount > 1) return {};
  const delivery = {};
  for (const [field, value] of [["firstReasoningSamplesMs", firstReasoningMs], ["firstContentSamplesMs", firstContentMs]]) {
    if (Number.isFinite(value) && value >= 0) {
      delivery[field] = [
        ...(Array.isArray(stats?.[field]) ? stats[field] : []), value + headerMs,
      ].slice(-MAX_THROUGHPUT_SAMPLES);
    }
  }
  const tokens = positiveNumber(completionTokens);
  const duration = positiveNumber(generationMs);
  if (!tokens || !duration) {
    return delivery;
  }
  const tokensPerSecond = tokens / (duration / 1_000);
  const previousEwma = positiveNumber(stats?.ewmaTokensPerSecond);
  return {
    ...delivery,
    ewmaTokensPerSecond: previousEwma
      ? previousEwma * (1 - EWMA_ALPHA) + tokensPerSecond * EWMA_ALPHA
      : tokensPerSecond,
    tokensPerSecondSamples: [
      ...(Array.isArray(stats?.tokensPerSecondSamples)
        ? stats.tokensPerSecondSamples
        : []),
      tokensPerSecond,
    ].slice(-MAX_THROUGHPUT_SAMPLES),
    lastCompletionTokens: Math.round(tokens),
    lastGenerationMs: Math.round(duration),
  };
}

export function estimatedGenerationMs(stats, outputTokens) {
  const tokensPerSecond = positiveNumber(stats?.ewmaTokensPerSecond);
  const tokens = positiveNumber(outputTokens);
  return tokensPerSecond && tokens
    ? (tokens / tokensPerSecond) * 1_000
    : null;
}

export function modelThroughputMetrics(stats) {
  const samples = Array.isArray(stats?.tokensPerSecondSamples)
    ? stats.tokensPerSecondSamples
    : [];
  return {
    delivery: {
      scope: "provider_headers_and_body",
      first_reasoning_ms: {
        p50: percentile(stats?.firstReasoningSamplesMs, 50),
        p95: percentile(stats?.firstReasoningSamplesMs, 95),
      },
      first_content_ms: {
        p50: percentile(stats?.firstContentSamplesMs, 50),
        p95: percentile(stats?.firstContentSamplesMs, 95),
      },
    },
    sample_count: samples.length,
    tokens_per_second: {
      ewma: rounded(stats?.ewmaTokensPerSecond),
      p50: percentile(samples, 50),
      p95: percentile(samples, 95),
    },
    last_completion_tokens: stats?.lastCompletionTokens ?? null,
    last_generation_ms: stats?.lastGenerationMs ?? null,
  };
}
