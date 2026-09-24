import { DurableObject, WorkflowEntrypoint } from "cloudflare:workers";
import { KnowledgeAuthority } from "./authority.mjs";
import { dispatchKnowledge, maintainKnowledge } from "./service.mjs";
import { runIngestion } from "./ingestion.mjs";
import { errorReply, fail, fields, readJson, reply } from "./contracts.mjs";

export class KnowledgeCatalogue extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.authority = new KnowledgeAuthority(ctx.storage);
  }

  async fetch(request) {
    try {
      if (request.method !== "POST" || new URL(request.url).pathname !== "/dispatch") fail("not_found", "Unknown catalogue route.", 404);
      const body = await readJson(request);
      fields(body, ["operation", "payload"], ["operation", "payload"]);
      return reply(await this.authority.call(body.operation, body.payload));
    } catch (error) { return errorReply(error); }
  }
}

export class KnowledgeIngestion extends WorkflowEntrypoint {
  async run(event, step) { return runIngestion(this.env, step, event.payload.job_id); }
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (request.method !== "POST" || url.origin !== "http://knowledge.internal" || url.pathname !== "/v1/dispatch"
        || url.search || url.hash || url.username || url.password) fail("not_found", "Unknown Knowledge route.", 404);
      const body = await readJson(request);
      return reply(await dispatchKnowledge(env, body, { signal: request.signal }));
    } catch (error) { return errorReply(error); }
  },
  async scheduled(_event, env, ctx) { ctx.waitUntil(maintainKnowledge(env)); },
};
