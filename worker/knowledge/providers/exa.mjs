import { invalidResponse, jsonPost, requestJSON, requireArray } from "./transport.mjs";
import { anyPublicHost } from "../contracts.mjs";
import { liveAcquisition, observation, queryText, requireSourceURL, sourceOperation, sourceURL } from "./source-policy.mjs";

const RESULTS_BY_MODE = { economy: 5, smart: 6, deep: 10 };

export async function retrieveExa(intent, context) {
  const acquisition = Boolean(intent.source_url);
  const source = acquisition ? requireSourceURL(intent.source_url, intent.allowed_hosts, "exa") : null;
  if (!acquisition && !intent.allowed_hosts?.length) return { observations: [], warnings: ["approved_source_hosts_required"] };
  const live = liveAcquisition(intent);
  const results = RESULTS_BY_MODE[intent.mode] ?? RESULTS_BY_MODE.smart;
  // Stay within the 1 MiB response bound when more pages are requested.
  const contents = { text: { maxCharacters: results > 6 ? 60000 : 100000 }, highlights: false, subpages: 0 };
  // livecrawl is deprecated; maxAgeHours 0 requests a fresh crawl.
  if (live) Object.assign(contents, { maxAgeHours: 0, livecrawlTimeout: 10000 });
  const body = acquisition ? { urls: [source], ...contents } : {
    query: queryText(intent, "exa"), type: intent.mode === "deep" ? "auto" : "fast", numResults: results,
    ...(anyPublicHost(intent.allowed_hosts) ? {} : { includeDomains: intent.allowed_hosts }), contents,
  };
  const suffix = acquisition ? "contents" : "search";
  const operation = acquisition ? await sourceOperation(suffix, source) : suffix;
  const data = await requestJSON("exa", operation, `https://api.exa.ai/${suffix}`,
    jsonPost(body), context);
  const found = requireArray(data?.results, "exa");
  if (acquisition && found.some((item) => sourceURL(item?.id || item?.url, intent.allowed_hosts) !== source)) {
    throw invalidResponse("exa");
  }
  if ((acquisition || live) && Array.isArray(data.statuses) && data.statuses.some((status) => status?.status !== "success")) {
    throw invalidResponse("exa");
  }
  const observations = found.slice(0, acquisition ? 1 : results)
    .map((item) => observation("exa", item, intent.allowed_hosts)).filter(Boolean);
  for (const item of observations) {
    if (item.kind === "source_excerpt" && live) item.freshness = "live";
  }
  const warnings = found.length > observations.length ? ["exa_results_filtered_by_source_policy"] : [];
  if (found.some((item) => typeof item?.text === "string" && item.text.length > 100000)) warnings.push("exa_content_truncated");
  return { observations, warnings };
}
