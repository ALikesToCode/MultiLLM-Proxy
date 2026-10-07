import { fail } from "./contracts.mjs";
import { parseFind, parseGet, parseSync } from "./skills-validation.mjs";

export async function dispatchSkills(env, operation, principal, payload, options = {}) {
  const action = operation.slice("skills.".length);
  const parsed = action === "find" ? parseFind(payload) : action === "get" ? parseGet(payload) : parseSync(payload);
  const store = options.skills ?? (env.KNOWLEDGE_SKILLS && {
    async call(operation, payload, principal) {
      const stub = env.KNOWLEDGE_SKILLS.get(env.KNOWLEDGE_SKILLS.idFromName("personal"));
      const response = await stub.fetch("http://skills.internal/dispatch", { method: "POST",
        headers: { "content-type": "application/json" }, body: JSON.stringify({ operation, payload, principal }), signal: AbortSignal.timeout(50000) });
      const body = await response.json();
      if (!response.ok || body.version !== 1) fail(body.error?.code ?? "skills_unavailable", body.error?.message ?? "Skills storage is unavailable.", response.ok ? 503 : response.status);
      return body.result;
    },
  });
  if (!store) fail("skills_unavailable", "Configure the Knowledge skills binding.", 503);
  return store.call(action, parsed, principal.id);
}
