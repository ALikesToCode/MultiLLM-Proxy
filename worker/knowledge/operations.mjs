import { fail } from "./contracts.mjs";
import { ProviderError } from "./providers/errors.mjs";

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
