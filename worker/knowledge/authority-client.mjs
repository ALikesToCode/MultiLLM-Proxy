import { fail, KnowledgeError } from "./contracts.mjs";

export function getAuthority(env) {
  if (!env.KNOWLEDGE_AUTHORITY) fail("storage_unavailable", "The Knowledge catalogue binding is not configured.", 503);
  const stub = env.KNOWLEDGE_AUTHORITY.get(env.KNOWLEDGE_AUTHORITY.idFromName("personal"));
  return {
    async call(operation, payload = {}) {
      const response = await stub.fetch("http://catalogue.internal/dispatch", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ operation, payload }),
      });
      const body = await response.json();
      if (!response.ok) throw new KnowledgeError(body.error?.code ?? "storage_unavailable", body.error?.message ?? "The catalogue is unavailable.", response.status);
      if (body.version !== 1 || !Object.hasOwn(body, "result")) fail("storage_unavailable", "The catalogue returned an invalid response.", 503);
      return body.result;
    },
  };
}
