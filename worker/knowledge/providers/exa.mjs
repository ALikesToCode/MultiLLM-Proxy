import { invalidResponse, jsonPost, requestJSON, requireArray } from "./transport.mjs";
import { observation, queryText, requireSourceURL, sourceOperation, sourceURL } from "./source-policy.mjs";

export async function retrieveExa(intent, context) {
  const acquisition = Boolean(intent.source_url);
  const source = acquisition ? requireSourceURL(intent.source_url, intent.allowed_hosts, "exa") : null;
  if (!acquisition && !intent.allowed_hosts?.length) return { observations: [], warnings: ["approved_source_hosts_required"] };
  const contents = { text: { maxCharacters: 100000 }, highlights: false, subpages: 0 };
  const body = acquisition ? { urls: [source], ...contents } : {
    query: queryText(intent, "exa"), type: "fast", numResults: 5,
    includeDomains: intent.allowed_hosts, contents,
  };
  const suffix = acquisition ? "contents" : "search";
  const operation = acquisition ? await sourceOperation(suffix, source) : suffix;
  const data = await requestJSON("exa", operation, `https://api.exa.ai/${suffix}`,
    jsonPost(body, { "x-api-key": context.env.EXA_API_KEY }), context);
  const results = requireArray(data?.results, "exa");
  if (acquisition && results.some((item) => sourceURL(item?.id || item?.url, intent.allowed_hosts) !== source)) {
    throw invalidResponse("exa");
  }
  if (acquisition && Array.isArray(data.statuses) && data.statuses.some((status) => status?.status === "error")) {
    throw invalidResponse("exa");
  }
  const observations = results.slice(0, acquisition ? 1 : 5)
    .map((item) => observation("exa", item, intent.allowed_hosts)).filter(Boolean);
  const warnings = results.length > observations.length ? ["exa_results_filtered_by_source_policy"] : [];
  if (results.some((item) => typeof item?.text === "string" && item.text.length > 100000)) warnings.push("exa_content_truncated");
  return { observations, warnings };
}
