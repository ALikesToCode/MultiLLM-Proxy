import { fail } from "./contracts.mjs";
import { checkImports, importSkill, reportSkills } from "./skills-import.mjs";
import { discoverSkills, previewSkill } from "./skills-market.mjs";
import { parseFind, parseGet, parseSync } from "./skills-validation.mjs";

function skillsStore(env, options) {
  return options.skills ?? (env.KNOWLEDGE_SKILLS && {
    async call(operation, payload, principal) {
      const stub = env.KNOWLEDGE_SKILLS.get(env.KNOWLEDGE_SKILLS.idFromName("personal"));
      const response = await stub.fetch("http://skills.internal/dispatch", { method: "POST",
        headers: { "content-type": "application/json" }, body: JSON.stringify({ operation, payload, principal }), signal: AbortSignal.timeout(50000) });
      const body = await response.json();
      if (!response.ok || body.version !== 1) fail(body.error?.code ?? "skills_unavailable", body.error?.message ?? "Skills storage is unavailable.", response.ok ? 503 : response.status);
      return body.result;
    },
  });
}

export async function dispatchSkills(env, operation, principal, payload, options = {}) {
  const action = operation.slice("skills.".length);
  // External previews are stateless reads and never touch the operator library.
  if (action === "preview") return previewSkill(payload, options);
  const store = skillsStore(env, options);
  const bound = store && { call: (name, body) => store.call(name, body, principal.id) };
  if (action === "discover") return discoverSkills(env, payload, bound && {
    find: query => bound.call("find", parseFind(query)),
    ledger: (name, body) => bound.call(name, body),
  }, options);
  if (action === "import") return importSkill(env, payload, bound, options);
  if (action === "report") return reportSkills(env, payload, bound, options);
  const parsed = action === "find" ? parseFind(payload) : action === "get" ? parseGet(payload) : parseSync(payload);
  if (!store) fail("skills_unavailable", "Configure the Knowledge skills binding.", 503);
  return store.call(action, parsed, principal.id);
}

// The hourly cron checks a few imported skills against their upstream; nothing is applied.
export async function watchImportedSkills(env, options = {}) {
  const store = skillsStore(env, options);
  if (!store) return 0;
  return checkImports(env, { call: (name, body) => store.call(name, body, "scheduler") }, options);
}
