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
    return env.KNOWLEDGE_SERVICE.fetch("http://knowledge.internal/v1/dispatch", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload), signal: request.signal,
    });
  } catch (error) { return errorReply(error); }
}
