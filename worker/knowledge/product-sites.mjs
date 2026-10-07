import { fail, fields, publicHost, string } from "./contracts.mjs";
import { digest, site } from "./evidence.mjs";

export const SITE_LIMIT = 64;
const PRODUCT_LIMIT = 400;
export const PAGE_LIMIT = 10000;
const SCAN_LIMIT = 100000;
const PAGE_SIZE = 1000;
const PREFIX = "product-sites:";
const LEGACY = "product-site-artifact:";
const LEARNED = "product-site-page:";
const COUNT = "product-site-page-count";
const SCHEMA = "product-site-page-schema";
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
  await migrateIdentities(tx);
  return await tx.get(`${PREFIX}${product}`) ?? empty(product);
}

export function publicProductSites(registry) {
  return { ...registry, sites: Object.fromEntries(Object.entries(registry.sites)
    .map(([host, { identity_epoch: _epoch, ...entry }]) => [host, entry])) };
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
    entry = { verified: 0, first_seen: timestamp, last_seen: timestamp, pinned: false,
      identity_epoch: registry.revision + 1 };
    registry.sites[host] = entry;
  }
  entry.verified += verified;
  if (timestamp < entry.first_seen) entry.first_seen = timestamp;
  if (timestamp > entry.last_seen) entry.last_seen = timestamp;
  return true;
}

// Page through retained manifests; exceeding the total cap fails rather than trusting a partial rebuild.
async function listAll(tx, prefix, maximum) {
  const records = new Map();
  let startAfter;
  while (records.size < maximum) {
    const limit = Math.min(PAGE_SIZE, maximum - records.size);
    const page = await tx.list({ prefix, limit,
      ...(startAfter ? { startAfter } : {}) });
    if (!page.size) return records;
    for (const [key, value] of page) records.set(key, value);
    if (page.size < limit) return records;
    startAfter = [...page.keys()].at(-1);
  }
  if ((await tx.list({ prefix, startAfter, limit: 1 })).size) {
    fail("product_sites_limit", "The product-site rebuild scan limit was exceeded.", 409);
  }
  return records;
}

async function pageIdentity(artifact, timestamp) {
  const host = site(artifact.canonical_url);
  if (!artifact.product || !host) return null;
  return { page_id: await digest(`${artifact.product}\0${artifact.canonical_url}`), product: artifact.product,
    site: host, first_seen: timestamp, last_seen: timestamp, identity_epoch: null };
}

const oldestFirst = ([a, x], [b, y]) => x.last_seen.localeCompare(y.last_seen) || a.localeCompare(b);
const slotKey = index => `${LEARNED}${String(index).padStart(5, "0")}`;

function decrement(registry, identity) {
  const entry = registry.sites[identity.site];
  // A site may have been evicted and learned again while its old page markers survived.
  if (!entry || identity.identity_epoch === null || identity.identity_epoch !== entry.identity_epoch) return;
  entry.verified = Math.max(0, entry.verified - 1);
  if (!entry.verified && !entry.pinned) delete registry.sites[identity.site];
  registry.revision++;
}

async function retainedPages(tx, product) {
  const pages = new Map();
  for (const artifact of (await listAll(tx, "artifact:", SCAN_LIMIT)).values()) {
    if (product && artifact.product !== product) continue;
    const identity = await pageIdentity(artifact, artifact.published_at || artifact.fetched_at);
    if (!identity) continue;
    const previous = pages.get(identity.page_id);
    if (previous) {
      previous.first_seen = [previous.first_seen, identity.first_seen].sort()[0];
      previous.last_seen = [previous.last_seen, identity.last_seen].sort().at(-1);
    } else pages.set(identity.page_id, identity);
  }
  return pages;
}

function resetLearned(registry, identities) {
  const groups = new Map();
  for (const identity of identities.values()) {
    if (identity.product !== registry.product) continue;
    const group = groups.get(identity.site) ?? { verified: 0, first_seen: identity.first_seen,
      last_seen: identity.last_seen, pinned: false, identity_epoch: registry.revision + 1 };
    group.verified++;
    group.first_seen = [group.first_seen, identity.first_seen].sort()[0];
    group.last_seen = [group.last_seen, identity.last_seen].sort().at(-1);
    groups.set(identity.site, group);
  }
  const pins = Object.entries(registry.sites).filter(([, entry]) => entry.pinned);
  registry.sites = Object.fromEntries(pins.map(([host, entry]) => [host, {
    ...entry, ...(groups.get(host) ?? { verified: 0 }), pinned: true,
  }]));
  // Fill the bounded registry with the strongest remaining historical sites.
  const ranked = [...groups].filter(([host]) => !registry.sites[host])
    .sort(([a, x], [b, y]) => y.verified - x.verified || y.last_seen.localeCompare(x.last_seen) || a.localeCompare(b));
  for (const [host, entry] of ranked.slice(0, SITE_LIMIT - pins.length)) registry.sites[host] = entry;
  for (const identity of identities.values()) {
    if (identity.product === registry.product) identity.identity_epoch = registry.sites[identity.site]?.identity_epoch ?? null;
  }
}

async function replaceIdentities(tx, identities, previous) {
  const slots = [...identities.values()];
  // Durable storage batches are bounded, too; rebuild runs in the catalogue transaction.
  for (let start = 0; start < slots.length; start += 128) {
    await tx.put(Object.fromEntries(slots.slice(start, start + 128).map((entry, index) => [slotKey(start + index), entry])));
  }
  for (const key of previous.keys()) if (Number(key.slice(LEARNED.length)) >= slots.length) await tx.delete(key);
  await tx.put(COUNT, slots.length);
}

async function migrateIdentities(tx) {
  if (await tx.get(SCHEMA) === 2) return;
  const legacy = await listAll(tx, LEGACY, PAGE_LIMIT);
  if (legacy.size) {
    // Revision markers lack URLs; retained manifests provide a safe one-time backfill.
    const registries = await tx.list({ prefix: PREFIX, limit: PRODUCT_LIMIT });
    const pages = await retainedPages(tx);
    const identities = new Map([...pages].filter(([, entry]) => registries.has(`${PREFIX}${entry.product}`))
      .sort(oldestFirst).slice(-PAGE_LIMIT));
    for (const registry of registries.values()) {
      resetLearned(registry, identities);
      registry.revision++;
      await tx.put(`${PREFIX}${registry.product}`, registry);
    }
    await replaceIdentities(tx, identities, await listAll(tx, LEARNED, PAGE_LIMIT));
    for (const key of legacy.keys()) await tx.delete(key);
    await tx.delete("product-site-artifact-count");
  }
  await tx.put(SCHEMA, 2);
}

/** Distinct page identities outlive expiry; revised or reacquired pages only refresh recency. */
export async function learnProductSite(tx, artifact, now) {
  await migrateIdentities(tx);
  const identity = await pageIdentity(artifact, new Date(now).toISOString());
  if (!identity) return false;
  const identities = await listAll(tx, LEARNED, PAGE_LIMIT);
  const previous = [...identities].find(([, entry]) => entry.page_id === identity.page_id);
  const registry = await getProductSites(tx, artifact.product);
  if (previous) {
    const [key, existing] = previous;
    existing.last_seen = identity.last_seen;
    const entry = registry.sites[existing.site];
    if (entry && existing.identity_epoch !== null && existing.identity_epoch === entry.identity_epoch) entry.last_seen = identity.last_seen;
    await tx.put({ [key]: existing, [`${PREFIX}${artifact.product}`]: registry });
    return false;
  }
  if (!await roomForProduct(tx, artifact.product)) return false;
  const changes = {};
  let key;
  if (identities.size >= PAGE_LIMIT) {
    const victim = [...identities].sort(oldestFirst)[0];
    key = victim[0];
    const affected = victim[1].product === artifact.product ? registry : await getProductSites(tx, victim[1].product);
    decrement(affected, victim[1]);
    changes[`${PREFIX}${victim[1].product}`] = affected;
  } else {
    for (let index = 0; index < PAGE_LIMIT; index++) if (!identities.has(slotKey(index))) { key = slotKey(index); break; }
  }
  const added = addSite(registry, identity.site, identity.last_seen);
  if (added) {
    identity.identity_epoch = registry.sites[identity.site].identity_epoch;
    registry.revision++;
  }
  // Reuse the evicted slot so counts, victim and new identity change atomically.
  await tx.put({ ...changes, [key]: identity, [`${PREFIX}${artifact.product}`]: registry,
    [COUNT]: Math.min(PAGE_LIMIT, identities.size + 1) });
  return added;
}

async function rebuildProductSites(tx, registry) {
  const previous = await listAll(tx, LEARNED, PAGE_LIMIT);
  const identities = new Map([...previous.values()].filter(entry => entry.product !== registry.product)
    .map(entry => [entry.page_id, entry]));
  for (const [key, identity] of await retainedPages(tx, registry.product)) identities.set(key, identity);
  const affected = new Map();
  // Discard the oldest identities in one bounded pass, including other products if needed.
  const ranked = [...identities].sort(oldestFirst);
  for (const [key, victim] of ranked.slice(0, Math.max(0, identities.size - PAGE_LIMIT))) {
    if (victim.product !== registry.product) {
      const other = affected.get(victim.product) ?? await getProductSites(tx, victim.product);
      decrement(other, victim);
      affected.set(victim.product, other);
    }
    identities.delete(key);
  }
  resetLearned(registry, identities);
  for (const [product, other] of affected) await tx.put(`${PREFIX}${product}`, other);
  await replaceIdentities(tx, identities, previous);
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
  return publicProductSites(registry);
}

export async function productSitesSummary(tx) {
  await migrateIdentities(tx);
  const registries = [...(await tx.list({ prefix: PREFIX, limit: PRODUCT_LIMIT })).values()];
  return { products: registries.length, sites: registries.reduce((count, registry) => count + Object.keys(registry.sites).length, 0),
    blocked: registries.reduce((count, registry) => count + Object.keys(registry.blocked).length, 0),
    artifact_identities: await tx.get(COUNT) ?? 0, product_limit: PRODUCT_LIMIT, artifact_identity_limit: PAGE_LIMIT };
}
