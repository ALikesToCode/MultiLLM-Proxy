import { fields, fail, integer, publicUrl } from "./contracts.mjs";

// One transaction validates all citations against the same policy and source revisions.
export async function validateMemoCitations(tx, input, policy, now) {
  fields(input, ["citations", "policy_revision"], ["citations", "policy_revision"]);
  integer(input.policy_revision, 1, Number.MAX_SAFE_INTEGER, "policy_revision");
  if (!Array.isArray(input.citations) || !input.citations.length || input.citations.length > 100) fail("invalid_memo", "Provide at most 100 citations.");
  if (!policy.enabled || policy.revision !== input.policy_revision) return { valid: false };
  const sources = new Map();
  for (const citation of input.citations) {
    fields(citation, ["artifact_id", "content_hash", "expires_at"], ["artifact_id", "content_hash", "expires_at"]);
    if (!/^[a-f0-9]{64}$/.test(citation.artifact_id ?? "") || !/^[a-f0-9]{64}$/.test(citation.content_hash ?? "")
      || !Number.isFinite(Date.parse(citation.expires_at))) fail("invalid_memo", "Invalid citation manifest.");
    const artifact = await tx.get(`artifact:${citation.artifact_id}`);
    if (!artifact || artifact.status !== "published" || artifact.content_hash !== citation.content_hash
      || !(Date.parse(artifact.expires_at) > now) || !(Date.parse(citation.expires_at) > now)
      || !policy.providers[artifact.provider]?.enabled || !policy.providers[artifact.provider]?.retention_allowed) return { valid: false };
    if (!sources.has(artifact.source_id)) sources.set(artifact.source_id, await tx.get(`source:${artifact.source_id}`));
    const source = sources.get(artifact.source_id);
    if (!source?.enabled || source.current_artifact !== artifact.id) return { valid: false };
    try { publicUrl(artifact.canonical_url, policy.allowed_hosts); }
    catch { return { valid: false }; }
  }
  return { valid: true };
}
