import { fail } from "./contracts.mjs";
import { parseHandoff } from "./handoff-contracts.mjs";
import { retentionAllowsContent } from "../retention-policy.mjs";

export async function dispatchHandoff(env, principal, operation, payload, retentionPolicy) {
  const name = operation.slice("handoffs.".length);
  if (name === "save" && !retentionAllowsContent(retentionPolicy)) {
    fail("retention_forbidden", "Handoff content cannot be saved under zero retention.", 409);
  }
  parseHandoff(name, payload);
  if (!env.KNOWLEDGE_HANDOFFS) fail("handoffs_unavailable", "Configure the Knowledge handoff binding.", 503);
  let timer;
  try {
    const stub = env.KNOWLEDGE_HANDOFFS.get(env.KNOWLEDGE_HANDOFFS.idFromName(principal.id));
    return await Promise.race([(async () => {
      const response = await stub.fetch("http://handoffs.internal/dispatch", { method: "POST",
        headers: { "content-type": "application/json" }, body: JSON.stringify({ operation: name, payload,
          ...(retentionPolicy?.enabled ? { retention_policy: retentionPolicy } : {}) }), signal: AbortSignal.timeout(2000) });
      const body = await response.json();
      if (body.version !== 1) throw new Error("invalid_handoff_response");
      if (!response.ok) fail(body.error?.code || "handoffs_unavailable", body.error?.message || "Knowledge handoffs are unavailable.", response.status);
      return body.result;
    })(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("handoff_timeout")), 2000); })]);
  } catch (error) {
    if (error.code) throw error;
    fail("handoffs_unavailable", "Knowledge handoffs are unavailable.", 503);
  } finally { clearTimeout(timer); }
}
