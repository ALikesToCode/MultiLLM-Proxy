import { fail, fields, publicHost, string } from "./contracts.mjs";
import { site } from "./evidence.mjs";

export const SITE_LIMIT = 64;
const PRODUCT_LIMIT = 400;
const ARTIFACT_LIMIT = 10000;
const PREFIX = "product-sites:";
const LEARNED = "product-site-artifact:";
const COUNT = "product-site-artifact-count";
const empty = product => ({ product, sites: {}, blocked: {}, revision: 0 });

export function parseProductSites(input, update = false) {
  fields(input, update ? ["product", "pin", "unpin", "block", "unblock", "note", "rebuild"] : ["product"], ["product"]);
  const parsed = { ...input, product: string(input.product, 100, "product").toLowerCase() };
  for (const action of ["pin", "unpin", "block", "unblock"]) {
    if (input[action] === undefined) continue;
    if (!Array.isArray(input[action]) || input[action].length > SITE_LIMIT
      || input[action].some(host => !publicHost(host)) || new Set(input[action]).size !== input[action].length) {
      fail("invalid_request", `${action} requires up to 64 unique lowercase public hostnames.`);
    }
    // Management accepts hostnames, but all decisions use the same site approximation.
    parsed[action] = [...new Set(input[action].map(host => site(`https://${host}`)))];
  }
  if (input.note !== undefined) parsed.note = string(input.note, 500, "note", { optional: true });
  if (input.rebuild !== undefined && typeof input.rebuild !== "boolean") fail("invalid_request", "rebuild must be a boolean.");
  for (const [first, second] of [["pin", "unpin"], ["block", "unblock"]]) {
    if (parsed[first]?.some(host => parsed[second]?.includes(host))) fail("invalid_request", "Conflicting site actions.");
  }
  return parsed;
}

export function productSitesDecision(registry) {
  const entries = Object.entries(registry?.sites ?? {});
  return { sites: entries.filter(([, entry]) => entry.verified > 0 || entry.pinned).map(([host]) => host).sort(),
    blocked: Object.keys(registry?.blocked ?? {}).sort(),
    established: entries.filter(([, entry]) => entry.verified > 0).length >= 2
      || entries.reduce((total, [, entry]) => total + entry.verified, 0) >= 5 };
}

export async function getProductSites(tx, product) {
  return await tx.get(`${PREFIX}${product}`) ?? empty(product);
}

async function roomForProduct(tx, product) {
  return Boolean(await tx.get(`${PREFIX}${product}`)) || (await tx.list({ prefix: PREFIX, limit: PRODUCT_LIMIT })).size < PRODUCT_LIMIT;
}

function makeRoom(registry) {
  if (Object.keys(registry.sites).length < SITE_LIMIT) return true;
  const victim = Object.entries(registry.sites).filter(([, entry]) => !entry.pinned)
    .sort(([a, x], [b, y]) => x.verified - y.verified || x.last_seen.localeCompare(y.last_seen) || a.localeCompare(b))[0];
  if (!victim) return false;
  delete registry.sites[victim[0]];
  return true;
}

function addSite(registry, host, timestamp, verified = 1) {
  let entry = registry.sites[host];
  if (!entry) {
    if (!makeRoom(registry)) return false;
    entry = { verified: 0, first_seen: timestamp, last_seen: timestamp, pinned: false };
    registry.sites[host] = entry;
  }
  entry.verified += verified;
  if (timestamp < entry.first_seen) entry.first_seen = timestamp;
  if (timestamp > entry.last_seen) entry.last_seen = timestamp;
  return true;
}

/** Durable identities outlive artifact expiry, so reacquisition cannot inflate counts. */
export async function learnProductSite(tx, artifact, now) {
  const host = site(artifact.canonical_url);
  if (!artifact.product || !host || await tx.get(`${LEARNED}${artifact.id}`)) return false;
  const count = await tx.get(COUNT) ?? 0;
  if (count >= ARTIFACT_LIMIT || !await roomForProduct(tx, artifact.product)) return false;
  const registry = await getProductSites(tx, artifact.product);
  // Even when all sites are pinned, remember this identity so retries cannot later count it.
  const added = addSite(registry, host, new Date(now).toISOString());
  if (added) registry.revision++;
  // One atomic batch prevents a caught write failure from separating counts and identities.
  await tx.put({ ...(added ? { [`${PREFIX}${artifact.product}`]: registry } : {}),
    [`${LEARNED}${artifact.id}`]: { product: artifact.product }, [COUNT]: count + 1 });
  return added;
}

async function rebuildProductSites(tx, registry) {
  const artifacts = [...(await tx.list({ prefix: "artifact:", limit: 1000 })).values()]
    .filter(artifact => artifact.product === registry.product && site(artifact.canonical_url));
  const identities = await tx.list({ prefix: LEARNED, limit: ARTIFACT_LIMIT });
  const previous = [...identities].filter(([, entry]) => entry.product === registry.product).map(([key]) => key);
  const count = await tx.get(COUNT) ?? identities.size;
  if (count - previous.length + artifacts.length > ARTIFACT_LIMIT) fail("product_sites_limit", "The learned artifact identity store is full.", 409);
  const groups = new Map();
  for (const artifact of artifacts) {
    const host = site(artifact.canonical_url);
    const timestamp = artifact.published_at || artifact.fetched_at;
    const group = groups.get(host) ?? { verified: 0, first_seen: timestamp, last_seen: timestamp, pinned: false };
    group.verified++;
    if (timestamp < group.first_seen) group.first_seen = timestamp;
    if (timestamp > group.last_seen) group.last_seen = timestamp;
    groups.set(host, group);
  }
  const pins = Object.entries(registry.sites).filter(([, entry]) => entry.pinned);
  registry.sites = Object.fromEntries(pins.map(([host, entry]) => [host, {
    ...entry, ...(groups.get(host) ?? { verified: 0 }), pinned: true,
  }]));
  // Fill the bounded registry with the strongest remaining historical sites.
  const ranked = [...groups].filter(([host]) => !registry.sites[host])
    .sort(([a, x], [b, y]) => y.verified - x.verified || y.last_seen.localeCompare(x.last_seen) || a.localeCompare(b));
  for (const [host, entry] of ranked.slice(0, SITE_LIMIT - pins.length)) registry.sites[host] = entry;
  for (const key of previous) await tx.delete(key);
  for (const artifact of artifacts) await tx.put(`${LEARNED}${artifact.id}`, { product: registry.product });
  await tx.put(COUNT, count - previous.length + artifacts.length);
}

export async function updateProductSites(tx, input, now) {
  const parsed = parseProductSites(input, true);
  const registry = await getProductSites(tx, parsed.product);
  if (!await roomForProduct(tx, parsed.product)) fail("product_sites_limit", "The product-site catalogue has reached its limit.", 409);
  const timestamp = new Date(now).toISOString();
  for (const host of parsed.unpin ?? []) if (registry.sites[host]) {
    if (!registry.sites[host].verified) delete registry.sites[host];
    else registry.sites[host].pinned = false;
  }
  for (const host of parsed.unblock ?? []) delete registry.blocked[host];
  // Protect the whole pin batch before evicting learned entries for newly pinned sites.
  const pins = new Set(Object.entries(registry.sites).filter(([, entry]) => entry.pinned).map(([host]) => host));
  for (const host of parsed.pin ?? []) pins.add(host);
  if (pins.size > SITE_LIMIT) fail("product_sites_limit", "At most 64 sites can be pinned per product.", 409);
  if (new Set([...Object.keys(registry.blocked), ...(parsed.block ?? [])]).size > SITE_LIMIT) {
    fail("product_sites_limit", "At most 64 sites can be blocked per product.", 409);
  }
  for (const host of parsed.pin ?? []) if (registry.sites[host]) registry.sites[host].pinned = true;
  for (const host of parsed.pin ?? []) {
    addSite(registry, host, timestamp, 0);
    registry.sites[host].pinned = true;
  }
  for (const host of parsed.block ?? []) registry.blocked[host] = { at: timestamp, note: parsed.note ?? "" };
  if (parsed.rebuild) await rebuildProductSites(tx, registry);
  registry.revision++;
  await tx.put(`${PREFIX}${parsed.product}`, registry);
  return registry;
}

export async function productSitesSummary(tx) {
  const registries = [...(await tx.list({ prefix: PREFIX, limit: PRODUCT_LIMIT })).values()];
  return { products: registries.length, sites: registries.reduce((count, registry) => count + Object.keys(registry.sites).length, 0),
    blocked: registries.reduce((count, registry) => count + Object.keys(registry.blocked).length, 0),
    artifact_identities: await tx.get(COUNT) ?? 0, product_limit: PRODUCT_LIMIT, artifact_identity_limit: ARTIFACT_LIMIT };
}
