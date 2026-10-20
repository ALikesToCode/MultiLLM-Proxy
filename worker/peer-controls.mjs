/** Admission before content crosses an independently deployed runtime boundary. */
import { requireControlledPeer } from "./peer-capability.mjs";
import { resolvePrincipal } from "./knowledge-edge.mjs";
import { currentDataControls, legacyDataControls } from "./key-data-guards.mjs";
import { DispatchError } from "./provider-dispatch.mjs";

export async function delegationPolicy(request, env) {
  const headers = new Headers(request.headers);
  // Native protocols carry the same proxy credential under their SDK header.
  if (!headers.has("x-multillm-api-key") && !headers.has("authorization")) {
    const key = headers.get("x-api-key") || headers.get("x-goog-api-key")
      || (new URL(request.url).pathname.startsWith("/linkapi/") ? new URL(request.url).searchParams.get("key") : null);
    if (key) headers.set("x-multillm-api-key", key);
  }
  const resolved = await resolvePrincipal(new Request(request.url, { headers }), env);
  if (resolved?.denied) return null; // The existing authentication path returns its normal refusal.
  return resolved?.principal
    ? currentDataControls(env, { keyId: resolved.principal.id }) : legacyDataControls(env);
}

export async function admitContainerDelegation(request, env, container) {
  const headers = request.headers;
  if (!["authorization", "x-multillm-api-key", "x-api-key", "x-goog-api-key"].some(name => headers.has(name))
    && !(new URL(request.url).pathname.startsWith("/linkapi/") && new URL(request.url).searchParams.has("key"))) return;

  try {
    const policy = await delegationPolicy(request, env);
    await requireControlledPeer(policy, container, "https://container.internal/healthz");
  }
  catch { throw new DispatchError("key_data_controls_unavailable"); }
}
