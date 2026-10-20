/** Probe the actual peer before transmitting controlled content. */
import { controlled } from "./key-controls-capability.mjs";
import { DispatchError } from "./provider-dispatch.mjs";
export const capabilityHeader = "X-MultiLLM-Key-Controls";
export async function requirePeer(peer, url, minimum = 2) {
  try {
    const response = await peer.fetch(url, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(5000) });
    const capability = (await response.json()).key_controls;
    if (!response.ok || !Number.isInteger(capability?.protocol) || capability.protocol < minimum
      || minimum >= 2 && capability.enforcement !== true) throw Error();
  } catch { throw new DispatchError("key_controls_peer_unavailable"); }
}
export async function requireControlledPeer(policy, peer, url) {
  if (controlled(policy)) await requirePeer(peer, url);
}
export function requireControlledSender(policy, request) {
  if (controlled(policy) && request.headers.get(capabilityHeader) !== "2") throw new DispatchError("key_controls_peer_unavailable");
}
