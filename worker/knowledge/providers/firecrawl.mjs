import { invalidResponse, jsonPost, requestJSON } from "./transport.mjs";
import { liveAcquisition, observation, requireSourceURL, sourceOperation } from "./source-policy.mjs";

// A redirect that only adds or drops a trailing slash reaches the same page.
function samePage(requested, final) {
  const [a, b] = [new URL(requested), new URL(final)];
  const path = url => url.pathname.replace(/\/+$/, "") || "/";
  return a.origin === b.origin && a.search === b.search && path(a) === path(b);
}

export async function retrieveFirecrawl(intent, context) {
  if (!intent.source_url) return { observations: [], warnings: ["firecrawl_requires_source_url"] };
  const source = requireSourceURL(intent.source_url, intent.allowed_hosts, "firecrawl");
  const live = liveAcquisition(intent);
  const result = await requestJSON("firecrawl", await sourceOperation("scrape", source), "https://api.firecrawl.dev/v2/scrape", jsonPost({
    url: source, formats: ["markdown"], onlyMainContent: true,
    parsers: [], proxy: "basic", timeout: 10000, maxAge: live ? 0 : 172800000,
  }), context);
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
  if (item.kind === "source_excerpt" && live) item.freshness = "live";
  const warnings = data.markdown.length > 100000 ? ["firecrawl_content_truncated"] : [];
  // Keep the requested identity for the same page. A different page keeps its final URL, so
  // it is not retained under the requested source, whose URL may carry version evidence.
  if (samePage(source, item.url)) item.url = source;
  else warnings.push("firecrawl_source_redirected");
  return { observations: [item], warnings };
}
