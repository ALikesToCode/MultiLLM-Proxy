import { retrieveContext7 } from "./context7.mjs";
import { retrieveExa } from "./exa.mjs";
import { retrieveFirecrawl } from "./firecrawl.mjs";
import { retrieveDeepWiki, retrieveMintlify } from "./mcp.mjs";
import { ProviderError } from "./transport.mjs";
import { sourceURL } from "./source-policy.mjs";

export const PROVIDERS = Object.freeze([
  { id: "context7", label: "Context7", credential_env: "CONTEXT7_API_KEY", docs_url: "https://github.com/upstash/context7/blob/master/docs/api-guide.mdx", capabilities: ["library_context"], kind: "discovery" },
  { id: "firecrawl", label: "Firecrawl", credential_env: "FIRECRAWL_API_KEY", docs_url: "https://docs.firecrawl.dev/api-reference/endpoint/scrape", capabilities: ["source_acquisition"], kind: "source_excerpt" },
  { id: "exa", label: "Exa", credential_env: "EXA_API_KEY", docs_url: "https://github.com/exa-labs/openapi-spec/blob/master/exa-openapi-spec.yaml", capabilities: ["search", "source_acquisition"], kind: "source_excerpt" },
  { id: "mintlify", label: "Mintlify Index", credential_env: null, docs_url: "https://github.com/mintlify/index", capabilities: ["context"], kind: "derived_context" },
  { id: "deepwiki", label: "DeepWiki", credential_env: null, docs_url: "https://docs.devin.ai/work-with-devin/deepwiki-mcp", capabilities: ["repository_context"], kind: "derived_context" },
].map((provider) => Object.freeze({ ...provider, capabilities: Object.freeze(provider.capabilities) })));

const ADAPTERS = { context7: retrieveContext7, exa: retrieveExa, firecrawl: retrieveFirecrawl, mintlify: retrieveMintlify, deepwiki: retrieveDeepWiki };

export function providerStatus(env = {}) {
  return PROVIDERS.map((provider) => ({
    ...provider,
    configured: provider.credential_env === null || (typeof env[provider.credential_env] === "string" && Boolean(env[provider.credential_env].trim())),
  }));
}

export async function retrieve(provider, intent, { env = {}, fetchImpl = fetch, invoke, signal } = {}) {
  const status = providerStatus(env).find((item) => item.id === provider);
  if (!status) throw new ProviderError("unknown", "unknown_knowledge_provider", "The requested knowledge provider is not supported.", 400);
  if (!status.configured) throw new ProviderError(provider, "provider_not_configured", "The knowledge provider credential is not configured.", 503);
  if (!intent || typeof intent !== "object" || !Array.isArray(intent.allowed_hosts) || intent.allowed_hosts.length > 50
      || intent.allowed_hosts.some((host) => typeof host !== "string" || !sourceURL(`https://${host}/`, [host]))) {
    throw new ProviderError(provider, "invalid_source_policy", "Knowledge retrieval requires an explicit list of public source hosts.", 400);
  }
  if (intent.source_url && !status.capabilities.includes("source_acquisition")) {
    return { observations: [], warnings: ["provider_does_not_acquire_sources"] };
  }
  return ADAPTERS[provider](intent, { env, fetchImpl, invoke, signal });
}

export { ProviderError } from "./transport.mjs";
