import { dropForeignProviderSections, site, SECTION_SEPARATOR } from "./evidence.mjs";
import { productSitesDecision } from "./product-sites.mjs";

const SEPARATOR = SECTION_SEPARATOR;

export function filterProviderSites(items, request, evidenceUrls, registry, mode = "observe") {
  const baseline = dropForeignProviderSections(items, request, evidenceUrls);
  const droppedSites = new Set();
  const flagged = [];
  const verifiedUrls = [...evidenceUrls];
  const verified = new Set(evidenceUrls.map(site));
  for (const item of items) {
    if (item.kind !== "provider_documentation" || typeof item.text !== "string") continue;
    for (const [, url] of item.text.matchAll(/Source: (\S+)/g)) { verified.add(site(url)); verifiedUrls.push(url); }
  }
  const decision = productSitesDecision(registry);
  const trustedSites = new Set(decision.sites);
  const reasonFor = host => {
    if (!host || !request.product || mode === "off") return null;
    if (Object.hasOwn(registry?.blocked ?? {}, host)) return "blocked";
    if (verified.has(host) || trustedSites.has(host)) return null;
    return decision.established ? "unverified_site" : null;
  };
  const dropped = {};
  const kept = [];
  for (const item of items) {
    if (item.kind !== "derived_context" || typeof item.text !== "string") { kept.push(item); continue; }
    const sectioned = item.text.includes(SEPARATOR);
    const remaining = [];
    for (const section of item.text.split(SEPARATOR)) {
      const host = site(section.match(/Source: (\S+)/)?.[1] ?? "");
      const reason = reasonFor(host);
      if (reason && flagged.length < 10) flagged.push({ provider: item.provider, site: host, reason });
      // The legacy heuristic only judges separated sections. Preserve that cold-start rule.
      const trusted = verified.has(host) || trustedSites.has(host);
      const legacyDrop = sectioned && dropForeignProviderSections([{ ...item, text: section + SEPARATOR }], request, verifiedUrls).dropped[item.provider];
      const remove = mode === "enforce" ? Boolean(reason || (!trusted && legacyDrop)) : Boolean(legacyDrop);
      if (remove) {
        dropped[item.provider] = (dropped[item.provider] ?? 0) + 1;
        if (host) droppedSites.add(host);
      } else remaining.push(section);
    }
    if (remaining.some(section => section.replace(/-/g, "").trim())) kept.push({ ...item, text: remaining.join(SEPARATOR) });
  }
  return { items: mode === "enforce" ? kept : baseline.items, dropped: mode === "enforce" ? dropped : baseline.dropped,
    droppedSites, flagged, baselineItems: baseline.items };
}
