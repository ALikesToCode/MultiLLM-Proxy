import { DurableObject, WorkflowEntrypoint } from "cloudflare:workers";
import { KnowledgeAuthority } from "./authority.mjs";
import { dispatchKnowledge, maintainKnowledge } from "./service.mjs";
import { runIngestion } from "./ingestion.mjs";
import { errorReply, fail, fields, KnowledgeError, readJson, reply } from "./contracts.mjs";
import { logFailure } from "../log.mjs";
import { HandoffStore } from "./handoff-store.mjs";
import { SkillsStore } from "./skills-store.mjs";
import { watchImportedSkills } from "./skills.mjs";
import { SYNC_REQUEST_BYTES } from "./skills-validation.mjs";
import { MemoStore } from "./memo-store.mjs";
import { SECRET_SCAN_HEADER } from "../secret-firewall.mjs";

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

export class KnowledgeHandoffs extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.handoffs = new HandoffStore(ctx.storage);
  }

  async fetch(request) {
    try {
      if (request.method !== "POST" || new URL(request.url).pathname !== "/dispatch") fail("not_found", "Unknown handoff route.", 404);
      const body = await readJson(request, 40 * 1024);
      fields(body, ["operation", "payload"], ["operation", "payload"]);
      return reply(this.handoffs.call(body.operation, body.payload));
    } catch (error) { return failure("knowledge_handoffs_failed", error); }
  }
}

export class KnowledgeSkills extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.skills = new SkillsStore(ctx.storage, env);
  }
  async fetch(request) {
    try {
      if (request.method !== "POST" || new URL(request.url).pathname !== "/dispatch") fail("not_found", "Unknown skills route.", 404);
      const body = await readJson(request, SYNC_REQUEST_BYTES);
      fields(body, ["operation", "payload", "principal"], ["operation", "payload", "principal"]);
      if (typeof body.principal !== "string" || !body.principal || body.principal.length > 256) fail("invalid_principal", "Invalid skills principal.", 403);
      return reply(await this.skills.call(body.operation, body.payload, body.principal));
    } catch (error) { return failure("knowledge_skills_failed", error); }
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
      const body = await readJson(request, SYNC_REQUEST_BYTES);
      if (body.operation !== "skills.sync" && new TextEncoder().encode(JSON.stringify(body)).length > 65536) fail("request_too_large", "Request is too large.", 413);
      let decision;
      const result = await dispatchKnowledge(env, body, { signal: request.signal, waitUntil: promise => ctx.waitUntil(promise), onSecretScan: value => { decision = value; } });
      const response = reply(result);
      if (decision?.header) response.headers.set(SECRET_SCAN_HEADER, decision.header);
      return response;
    } catch (error) { return failure("knowledge_request_failed", error); }
  },
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(maintainKnowledge(env).catch(error => { logFailure("knowledge_maintenance_failed", error); throw error; }));
    // Separate so an upstream check failure cannot stop catalogue maintenance.
    ctx.waitUntil(watchImportedSkills(env).catch(error => logFailure("knowledge_skills_watch_failed", error)));
  },
};
