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
  { completionTokens, generationMs } = {},
) {
  const tokens = positiveNumber(completionTokens);
  const duration = positiveNumber(generationMs);
  if (!tokens || !duration) {
    return {};
  }
  const tokensPerSecond = tokens / (duration / 1_000);
  const previousEwma = positiveNumber(stats?.ewmaTokensPerSecond);
  return {
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
