import { glmModelVariant } from "./model-selection.mjs";

function percentile(values, percentileValue) {
  if (!Array.isArray(values) || !values.length) {
    return null;
  }
  const ordered = [...values].sort((left, right) => left - right);
  const index = Math.max(
    0,
    Math.ceil((percentileValue / 100) * ordered.length) - 1,
  );
  return ordered[index];
}

function p95Latency(stats) {
  const ttfbSamples = stats?.ttfbSamplesMs ?? [];
  const totalSamples = stats?.totalSamplesMs ?? [];
  return {
    samples: Math.min(ttfbSamples.length, totalSamples.length),
    ttfbMs: percentile(ttfbSamples, 95),
    totalMs: percentile(totalSamples, 95),
  };
}

function sameRoute(left, right) {
  return (
    left.provider === right.provider &&
    left.credentialId === right.credentialId &&
    left.family === right.family
  );
}

function withinPremium(candidateLatency, baselineLatency, premiumPercent) {
  const multiplier = 1 + premiumPercent / 100;
  return (
    candidateLatency.ttfbMs <= baselineLatency.ttfbMs * multiplier &&
    candidateLatency.totalMs <= baselineLatency.totalMs * multiplier
  );
}

export function applyGlmQualityLatencyGuard(
  candidates,
  modelStats,
  preference,
  { premiumPercent = 20, minimumSamples = 3 } = {},
) {
  if (String(preference).toLowerCase() !== "glm") {
    return candidates.map((candidate) => ({
      ...candidate,
      routingRank: candidate.modelRank,
      qualityPromoted: false,
    }));
  }

  return candidates.map((candidate) => {
    const variant = glmModelVariant(candidate.model);
    if (variant.version !== "5.3" || variant.flash || variant.uncensored) {
      return {
        ...candidate,
        routingRank: candidate.modelRank,
        qualityPromoted: false,
      };
    }

    const flash = candidates.find((other) => {
      const otherVariant = glmModelVariant(other.model);
      return (
        sameRoute(candidate, other) &&
        otherVariant.version === "5.3" &&
        otherVariant.flash &&
        !otherVariant.uncensored
      );
    });
    if (!flash) {
      return {
        ...candidate,
        routingRank: candidate.modelRank,
        qualityPromoted: false,
      };
    }

    const candidateLatency = p95Latency(modelStats[candidate.key]);
    const flashLatency = p95Latency(modelStats[flash.key]);
    const enoughEvidence =
      candidateLatency.samples >= minimumSamples &&
      flashLatency.samples >= minimumSamples;
    const qualityPromoted =
      enoughEvidence &&
      withinPremium(candidateLatency, flashLatency, premiumPercent);
    return {
      ...candidate,
      routingRank: qualityPromoted
        ? flash.modelRank - 0.5
        : Math.max(candidate.modelRank, flash.modelRank + 0.5),
      qualityPromoted,
    };
  });
}
