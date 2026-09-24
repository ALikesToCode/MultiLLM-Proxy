import { invalidResponse, requestJSON, requireArray, ProviderError } from "./transport.mjs";
import { queryText, sourceURL } from "./source-policy.mjs";

function selectLibrary(results, intent) {
  const valid = results.filter((item) => typeof item?.id === "string" && /^\/[^/]+\/[^/]+(?:[/@][^/]+)?$/.test(item.id));
  const repository = intent.repository ? `/${intent.repository}`.toLowerCase() : null;
  return valid.find((item) => repository && item.id.toLowerCase() === repository)
    || valid.find((item) => typeof item.title === "string" && item.title.toLowerCase() === intent.product?.toLowerCase()) || valid[0];
}

function targetLibrary(library, version) {
  if (!version || !Array.isArray(library.versions)) return library.id;
  const match = library.versions.find((candidate) => typeof candidate === "string"
    && candidate.replace(/^v/, "") === String(version).replace(/^v/, ""));
  return match && !/[\s/@]/.test(match) ? `${library.id}/${match}` : library.id;
}

export async function retrieveContext7(intent, context) {
  const query = queryText(intent, "context7", 500);
  const product = intent.product || intent.repository;
  if (typeof product !== "string" || !product.trim() || product.length > 500) {
    throw new ProviderError("context7", "provider_product_required", "Context7 requires a product or public repository name.", 400);
  }
  const search = new URL("https://context7.com/api/v2/libs/search");
  search.search = new URLSearchParams({ libraryName: product, query }).toString();
  const data = await requestJSON("context7", "search", search.href, {}, context);
  const library = selectLibrary(requireArray(data?.results, "context7"), intent);
  if (!library) return { observations: [], warnings: ["context7_library_not_found"] };
  const endpoint = new URL("https://context7.com/api/v2/context");
  endpoint.search = new URLSearchParams({ libraryId: targetLibrary(library, intent.version), query, type: "json" }).toString();
  const docs = await requestJSON("context7", "context", endpoint.href, {}, context);
  if (!docs || !Array.isArray(docs.codeSnippets) || !Array.isArray(docs.infoSnippets)) throw invalidResponse("context7");
  const candidates = [
    ...docs.infoSnippets.map((item) => ({ url: item?.pageId, title: item?.breadcrumb })),
    ...docs.codeSnippets.map((item) => ({ url: item?.codeId, title: item?.pageTitle || item?.codeTitle })),
  ];
  const seen = new Set();
  const observations = [];
  for (const item of candidates) {
    const url = sourceURL(item.url, intent.allowed_hosts);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    observations.push({ kind: "discovery", url, title: typeof item.title === "string" ? item.title.slice(0, 500) : url, text: "", provider: "context7" });
    if (observations.length === 10) break;
  }
  const documentation = context7Documentation(library, docs, intent.allowed_hosts);
  if (documentation) observations.unshift(documentation);
  const warnings = ["context7_sources_require_acquisition"];
  if (intent.version) warnings.push("context7_source_version_unverified");
  return { observations, warnings };
}

const MAX_DOCUMENTATION_CHARACTERS = 60000;

// Context7's snippets are provider-extracted documentation, not byte-exact source text:
// they are returned as provider context with their source links, never as excerpts.
export function context7Documentation(library, docs, allowedHosts) {
  const sections = [];
  for (const item of docs.infoSnippets) {
    if (typeof item?.content !== "string" || !item.content.trim()) continue;
    const source = sourceURL(item.pageId, allowedHosts);
    sections.push([typeof item.breadcrumb === "string" ? `### ${item.breadcrumb}` : "", item.content.trim(),
      source ? `Source: ${source}` : ""].filter(Boolean).join("\n"));
  }
  for (const item of docs.codeSnippets) {
    const code = Array.isArray(item?.codeList) ? item.codeList.filter(entry => typeof entry?.code === "string" && entry.code.trim()) : [];
    if (!code.length) continue;
    const source = sourceURL(item.codeId, allowedHosts);
    sections.push([
      typeof item.codeTitle === "string" ? `### ${item.codeTitle}` : "",
      typeof item.codeDescription === "string" ? item.codeDescription.trim() : "",
      ...code.map(entry => `\`\`\`${typeof entry.language === "string" ? entry.language.replace(/[^\w+#.-]/g, "") : ""}\n${entry.code}\n\`\`\``),
      source ? `Source: ${source}` : "",
    ].filter(Boolean).join("\n"));
  }
  if (!sections.length) return null;
  let text = "";
  for (const section of sections) {
    if (text.length + section.length + 2 > MAX_DOCUMENTATION_CHARACTERS) break;
    text += (text ? "\n\n" : "") + section;
  }
  return { kind: "provider_documentation", provider: "context7", url: `https://context7.com${library.id}`,
    title: `Context7: ${typeof library.title === "string" ? library.title.slice(0, 200) : library.id}`, text: text || sections[0].slice(0, MAX_DOCUMENTATION_CHARACTERS) };
}
