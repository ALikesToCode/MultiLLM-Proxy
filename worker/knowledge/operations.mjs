import { fail } from "./contracts.mjs";

export async function metered(authority, operation, callback) {
  const reservation = await authority.call("reserve", operation);
  if (reservation.replay) fail("operation_already_submitted", "This operation was already submitted; inspect its durable receipt before retrying.", 409);
  let result;
  try { result = await callback(); }
  catch (error) {
    // A timeout or provider error does not establish that no work was charged.
    await authority.call("settle", { id: reservation.id, outcome: "unknown" }).catch(() => {});
    throw error;
  }
  await authority.call("settle", { id: reservation.id, outcome: "confirmed" });
  return result;
}
