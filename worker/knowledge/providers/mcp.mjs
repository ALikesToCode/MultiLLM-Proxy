import { invalidResponse, jsonPost, ProviderError, requestJSON } from "./transport.mjs";
import { queryText, sourceLinks } from "./source-policy.mjs";
import { anyPublicHost } from "../contracts.mjs";

function toolText(provider, response) {
  if (response?.jsonrpc !== "2.0" || response.id !== 1 || response.error || response.result?.isError) {
    throw new ProviderError(provider, "provider_tool_failed", "The knowledge provider tool could not complete the request.");
  }
  const result = response.result;
  if (typeof result?.structuredContent?.result === "string") return result.structuredContent.result;
  if (!Array.isArray(result?.content)) throw invalidResponse(provider);
  const texts = result.content.filter((item) => item?.type === "text" && typeof item.text === "string").map((item) => item.text);
  if (!texts.length) throw invalidResponse(provider);
  return texts.join("\n\n");
}

export async function callTool(provider, endpoint, name, args, context, operation = "context") {
  const response = await requestJSON(provider, operation, endpoint, jsonPost({
    jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args },
  }, { Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-03-26" }), context);
  return toolText(provider, response);
}

function derived(provider, text, url, intent) {
  const observations = [{ kind: "derived_context", provider, url, title: `${provider} context`, text: text.slice(0, 100000) }];
  for (const source of sourceLinks(text, intent.allowed_hosts)) {
    observations.push({ kind: "discovery", provider, url: source, title: source, text: "" });
  }
  return { observations, warnings: ["derived_context_requires_source_verification", ...(text.length > 100000 ? ["provider_content_truncated"] : [])] };
}

export async function retrieveMintlify(intent, context) {
  const args = { query: queryText(intent, "mintlify"), tokenBudget: 3000 };
  if (typeof intent.product === "string" && intent.product.trim()) args.product = intent.product.slice(0, 200);
  if (intent.allowed_hosts?.length && !anyPublicHost(intent.allowed_hosts)) args.includeDomains = intent.allowed_hosts;
  const text = await callTool("mintlify", "https://index.mintlify.com/mcp", "context", args, context);
  return derived("mintlify", text, "https://index.mintlify.com", intent);
}

export async function retrieveDeepWiki(intent, context) {
  if (typeof intent.repository !== "string" || !/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(intent.repository)
      || intent.repository.split("/").some((part) => /^\.+$/.test(part))) {
    throw new ProviderError("deepwiki", "provider_repository_required", "DeepWiki requires a public repository in owner/repo format.", 400);
  }
  const text = await callTool("deepwiki", "https://mcp.deepwiki.com/mcp", "ask_wiki_question", {
    repoName: intent.repository, question: queryText(intent, "deepwiki"),
  }, context);
  return derived("deepwiki", text, `https://deepwiki.com/${intent.repository}`, intent);
}
