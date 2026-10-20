import { bindingPrincipal } from "./provider-dispatch.mjs";
import { requireControlledPeer, requireControlledSender, capabilityHeader } from "./peer-capability.mjs";
import { SYNC_REQUEST_BYTES } from "./knowledge/skills-validation.mjs";
import { errorReply, fail, readJson } from "./knowledge/contracts.mjs";

export async function handleKnowledgeOutbound(request, env) {
  try {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.origin !== "http://knowledge.internal" || url.pathname !== "/v1/dispatch"
      || url.search || url.hash || url.username || url.password) fail("invalid_target", "Invalid Knowledge service target.", 400);
    if (!env.KNOWLEDGE_SERVICE) fail("knowledge_not_configured", "The private Knowledge service binding is not configured.", 503);
    const payload = await readJson(request, SYNC_REQUEST_BYTES);
    if (payload.operation !== "skills.sync" && new TextEncoder().encode(JSON.stringify(payload)).length > 65536) fail("request_too_large", "Request is too large.", 413);
    const source = bindingPrincipal(request, payload.principal?.id);
    if (source.keyId !== payload.principal?.id) fail("invalid_principal", "The dispatch principal does not match.", 403);
    const policy = await (await import("./key-data-guards.mjs")).currentDataControls(env, source);
    requireControlledSender(policy, request);
    await requireControlledPeer(policy, env.KNOWLEDGE_SERVICE, "http://knowledge.internal/ready");
    return env.KNOWLEDGE_SERVICE.fetch("http://knowledge.internal/v1/dispatch", {
      method: "POST", headers: { "content-type": "application/json", [capabilityHeader]: "2",
        "X-MultiLLM-Dispatch-Principal": JSON.stringify({ version: 1, username: payload.principal?.id }) }, body: JSON.stringify(payload), signal: request.signal,
    });
  } catch (error) { return errorReply(error); }
}
