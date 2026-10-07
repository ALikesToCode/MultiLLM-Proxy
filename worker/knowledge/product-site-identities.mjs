import { fail } from "./contracts.mjs";

export const PAGE_LIMIT = 10000;
export const PAGE_PREFIX = "product-site-page:";
export const LRU_PREFIX = "product-site-lru:";
export const COUNT = "product-site-page-count";
export const SCHEMA = "product-site-page-schema";
const PAGE_SIZE = 1000;
const WRITE_SIZE = 64; // Each identity writes a page record and its recency entry.

export const pageKey = pageId => `${PAGE_PREFIX}${pageId}`;
export const lruKey = identity => `${LRU_PREFIX}${identity.last_seen}:${identity.page_id}`;

// Yield one storage page at a time, rejecting overflow before a partial rebuild is saved.
export async function* scanRecords(tx, prefix, maximum) {
  let seen = 0;
  let startAfter;
  while (seen < maximum) {
    const limit = Math.min(PAGE_SIZE, maximum - seen);
    const page = await tx.list({ prefix, limit, ...(startAfter ? { startAfter } : {}) });
    if (!page.size) return;
    yield page;
    seen += page.size;
    if (page.size < limit) return;
    startAfter = [...page.keys()].at(-1);
  }
  if ((await tx.list({ prefix, startAfter, limit: 1 })).size) {
    fail("product_sites_limit", "The product-site rebuild scan limit was exceeded.", 409);
  }
}

export async function listIdentities(tx, prefix = PAGE_PREFIX) {
  const records = new Map();
  for await (const page of scanRecords(tx, prefix, PAGE_LIMIT)) {
    for (const [key, value] of page) records.set(key, value);
  }
  return records;
}

async function writeIdentities(tx, entries) {
  for (let start = 0; start < entries.length; start += WRITE_SIZE) {
    const writes = {};
    for (const identity of entries.slice(start, start + WRITE_SIZE)) {
      writes[pageKey(identity.page_id)] = identity;
      writes[lruKey(identity)] = identity.page_id;
    }
    await tx.put(writes);
  }
}

export async function replaceIdentities(tx, identities, previous) {
  // Remove prior recency entries even for pages whose timestamps changed on rebuild.
  const keys = [...previous].flatMap(([key, identity]) => [key, lruKey(identity)]);
  for (let start = 0; start < keys.length; start += 128) await tx.delete(keys.slice(start, start + 128));
  await writeIdentities(tx, [...identities.values()]);
  await tx.put(COUNT, identities.size);
}

export async function migratePageLayout(tx) {
  const previous = await listIdentities(tx);
  const identities = new Map([...previous.values()].map(entry => [entry.page_id, entry]));
  await replaceIdentities(tx, identities, previous);
  await tx.put(SCHEMA, 3);
}
