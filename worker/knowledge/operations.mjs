import { fail } from "./contracts.mjs";
import { ProviderError } from "./providers/errors.mjs";

// Refusals meaning the revision may no longer be retained under the current policy or source.
const RETENTION_REFUSALS = new Set(["provider_disabled", "source_not_allowed", "invalid_artifact", "artifact_expiring"]);

/**
 * Re-admit a revision after its snapshot write. If the policy or source changed during the
 * write, remove the bytes this write created so revoked content does not stay in storage.
 */
export async function confirmSnapshot(authority, corpus, artifact, written) {
  try { return await authority.call("artifact.save", { artifact }); }
  catch (error) {
    if (written?.created === true && RETENTION_REFUSALS.has(error?.code)) {
      try { await corpus.discardSnapshot(artifact); } catch { /* Expiry still covers the saved manifest. */ }
    }
    throw error;
  }
}

export async function metered(authority, operation, callback) {
  const reservation = await authority.call("reserve", operation);
  if (reservation.replay) fail("operation_already_submitted", "This operation was already submitted; inspect its durable receipt before retrying.", 409);
  let result;
  try { result = await callback(); }
  catch (error) {
    // Only a definitive pre-dispatch quota refusal can release this allowance.
    const rejected = error instanceof ProviderError && error.no_charge === true;
    await authority.call("settle", { id: reservation.id, outcome: rejected ? "confirmed" : "unknown", unused: rejected }).catch(() => {});
    throw error;
  }
  await authority.call("settle", { id: reservation.id, outcome: "confirmed" });
  return result;
}
