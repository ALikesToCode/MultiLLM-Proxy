import { publicUrl } from "./contracts.mjs";

export function eligibleArtifact(artifact, source, policy, now) {
  if (!artifact || artifact.status === "expiring" || !source?.enabled || !(Date.parse(artifact.expires_at) > now)
    || !policy.providers[artifact.provider]?.enabled || !policy.providers[artifact.provider]?.retention_allowed) return false;
  try { publicUrl(artifact.canonical_url, policy.allowed_hosts); }
  catch { return false; }
  return true;
}

// Retained live acquisitions are usable before publication; published revisions must be current.
export function eligibleCandidate(artifact, source, policy, now) {
  return eligibleArtifact(artifact, source, policy, now)
    && (artifact.status !== "published" || source.current_artifact === artifact.id);
}
