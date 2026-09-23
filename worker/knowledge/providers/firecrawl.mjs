import { invalidResponse, jsonPost, requestJSON } from "./transport.mjs";
import { observation, requireSourceURL, sourceOperation } from "./source-policy.mjs";

export async function retrieveFirecrawl(intent, context) {
  if (!intent.source_url) return { observations: [], warnings: ["firecrawl_requires_source_url"] };
  const source = requireSourceURL(intent.source_url, intent.allowed_hosts, "firecrawl");
  const result = await requestJSON("firecrawl", await sourceOperation("scrape", source), "https://api.firecrawl.dev/v2/scrape", jsonPost({
    url: source, formats: ["markdown"], onlyMainContent: true,
    parsers: [], proxy: "basic", timeout: 10000, maxAge: 172800000,
  }, { Authorization: `Bearer ${context.env.FIRECRAWL_API_KEY}` }), context);
  const data = result?.data;
  const metadata = data?.metadata;
  if (result?.success !== true || typeof data?.markdown !== "string" || !metadata || metadata.error
      || (metadata.statusCode !== undefined && (!Number.isInteger(metadata.statusCode) || metadata.statusCode < 200 || metadata.statusCode >= 300))) {
    throw invalidResponse("firecrawl");
  }
  if (metadata.contentType && !/^(?:text\/(?:html|plain|markdown)|application\/(?:xhtml\+xml|xml))(?:;|$)/i.test(metadata.contentType)) {
    return { observations: [], warnings: ["firecrawl_unsupported_source_format"] };
  }
  if (requireSourceURL(metadata.sourceURL || source, intent.allowed_hosts, "firecrawl") !== source) throw invalidResponse("firecrawl");
  const item = observation("firecrawl", {
    url: metadata.url || metadata.sourceURL || source,
    title: Array.isArray(metadata.title) ? metadata.title[0] : metadata.title,
    text: data.markdown,
  }, intent.allowed_hosts);
  if (!item) return { observations: [], warnings: ["firecrawl_redirect_outside_source_policy"] };
  return { observations: [item], warnings: data.markdown.length > 100000 ? ["firecrawl_content_truncated"] : [] };
}
