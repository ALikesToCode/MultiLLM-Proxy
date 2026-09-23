import { KnowledgeAuthority } from "../worker/knowledge/authority.mjs";
import { createArtifact } from "../worker/knowledge/evidence.mjs";
import { defaultPolicy } from "../worker/knowledge/policy.mjs";
import { parseQuery } from "../worker/knowledge/contracts.mjs";

class Storage {
  constructor() { this.values = new Map(); this.pending = Promise.resolve(); }
  async get(key) { return structuredClone(this.values.get(key)); }
  async put(key, value) { this.values.set(key, structuredClone(value)); }
  async delete(key) { this.values.delete(key); }
  async list({ prefix }) { return new Map([...this.values].filter(([key]) => key.startsWith(prefix)).map(([key, value]) => [key, structuredClone(value)])); }
  transaction(callback) {
    const result = this.pending.then(() => callback(this));
    this.pending = result.catch(() => {});
    return result;
  }
}

export const principal = { id: "fixture-reader", scopes: ["knowledge:read"] };
export const manager = { id: "fixture-manager", scopes: ["knowledge:read", "knowledge:manage"] };
export const request = changes => parseQuery({ query: "How are request size limits configured?", product: "flask", mode: "economy", ...changes });

export async function fixture() {
  const storage = new Storage();
  const authority = new KnowledgeAuthority(storage);
  const policy = defaultPolicy();
  policy.enabled = true;
  for (const name of ["firecrawl", "exa", "ai_search"]) Object.assign(policy.providers[name], {
    enabled: true, limit: 100, background_limit: 50, hard_limit_confirmed: true, retention_allowed: true,
  });
  await storage.put("policy", policy);
  const source = await authority.call("source.create", {
    url: "https://flask.palletsprojects.com/en/3.1.3/limits/", product: "flask", version: "3.1.3", provider: "firecrawl",
  });
  const text = "# Request size limits\n\nFlask applies configured limits to café and 東京 requests.";
  const snapshots = new Map();
  const cacheEntries = new Map();
  const rows = [];
  const counts = { searches: 0, providers: 0, writes: 0 };
  const corpus = {
    async search() { counts.searches++; return structuredClone(rows); },
    async getSnapshot(artifact) { return snapshots.get(artifact.id) ?? null; },
    async putSnapshot(artifact, value) { counts.writes++; snapshots.set(artifact.id, value); },
  };
  const cache = {
    async match(key) { return cacheEntries.get(key.url)?.clone(); },
    async put(key, value) { cacheEntries.set(key.url, value.clone()); },
  };
  const env = { KNOWLEDGE_SNAPSHOTS: {}, KNOWLEDGE_INDEX: {}, EXA_API_KEY: "synthetic-test-key" };
  const retrieve = async (provider, intent, { invoke }) => invoke(provider, "lookup", async () => {
    counts.providers++;
    return { observations: [{ kind: "source_excerpt", url: source.url, text, provider, freshness: "live" }], warnings: [] };
  });
  return {
    storage, authority, policy, source, text, snapshots, rows, corpus, cache, env, retrieve, counts,
    async published({ fresh = true } = {}) {
      const artifact = await createArtifact({ ...source, origin_checked: fresh }, text, "firecrawl");
      snapshots.set(artifact.id, text);
      await authority.call("artifact.save", { artifact });
      const job = await authority.call("job.enqueue", { source_id: source.id });
      await authority.call("job.publish", { id: job.id, artifact_id: artifact.id, item_id: "fixture-item", index_key: artifact.index_key });
      rows.push({ text, index_key: artifact.index_key, score: 0.9 });
      return artifact;
    },
  };
}
