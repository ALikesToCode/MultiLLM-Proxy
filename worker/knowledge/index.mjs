import { DurableObject, WorkflowEntrypoint } from "cloudflare:workers";
import { KnowledgeAuthority } from "./authority.mjs";
import { dispatchKnowledge, maintainKnowledge } from "./service.mjs";
import { runIngestion } from "./ingestion.mjs";
import { errorReply, fail, fields, KnowledgeError, readJson, reply } from "./contracts.mjs";
import { logFailure } from "../log.mjs";
import { MemoStore } from "./memo-store.mjs";

// Refusals are answers; unexpected faults and server-side failures are logged.
function failure(event, error) {
  if (!(error instanceof KnowledgeError) || error.status >= 500) logFailure(event, error, { code: error?.code ?? "knowledge_unavailable" });
  return errorReply(error);
}

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
    } catch (error) { return failure("knowledge_catalogue_failed", error); }
  }
}

export class KnowledgeMemos extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.memos = new MemoStore(ctx.storage);
  }

  async fetch(request) {
    try {
      if (request.method !== "POST" || new URL(request.url).pathname !== "/dispatch") fail("not_found", "Unknown memo route.", 404);
      // A 256 KiB bundle plus its bounded vector and citation manifests.
      const body = await readJson(request, 320 * 1024);
      fields(body, ["operation", "payload"], ["operation", "payload"]);
      return reply(this.memos.call(body.operation, body.payload));
    } catch (error) { return failure("knowledge_memos_failed", error); }
  }
}

export class KnowledgeIngestion extends WorkflowEntrypoint {
  async run(event, step) { return runIngestion(this.env, step, event.payload.job_id); }
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      if (request.method !== "POST" || url.origin !== "http://knowledge.internal" || url.pathname !== "/v1/dispatch"
        || url.search || url.hash || url.username || url.password) fail("not_found", "Unknown Knowledge route.", 404);
      const body = await readJson(request);
      return reply(await dispatchKnowledge(env, body, { signal: request.signal, waitUntil: promise => ctx.waitUntil(promise) }));
    } catch (error) { return failure("knowledge_request_failed", error); }
  },
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(maintainKnowledge(env).catch(error => { logFailure("knowledge_maintenance_failed", error); throw error; }));
  },
};
