import { digest } from "./evidence.mjs";

export async function cacheKey(principal, request, snapshot) {
  const identity = JSON.stringify({ principal: principal.id, scopes: [...principal.scopes].sort(), request,
    generation: snapshot.generation, policy_revision: snapshot.policy.revision });
  return new Request(`https://knowledge-cache.internal/evidence/${await digest(identity)}`);
}

export async function readCache(cache, key, now = Date.now()) {
  if (!cache) return null;
  try {
    const response = await cache.match(key);
    if (!response) return null;
    const entry = await response.json();
    if (!entry || entry.expires_at <= now || !Array.isArray(entry.bundle?.excerpts)) return null;
    return entry.bundle;
  } catch { return null; }
}

export async function writeCache(cache, key, bundle, ttl, now = Date.now()) {
  // Partial bundles reach here only with stable provider coverage notes, never failures.
  if (!cache || ttl < 1 || !["ok", "partial"].includes(bundle.status) || !bundle.excerpts.length) return;
  const expiry = Math.min(now + ttl * 1000, ...bundle.excerpts.map(item => Date.parse(item.expires_at)));
  if (!Number.isFinite(expiry) || expiry <= now) return;
  try {
    await cache.put(key, Response.json({ expires_at: expiry, bundle }, {
      headers: { "cache-control": `max-age=${Math.max(1, Math.floor((expiry - now) / 1000))}` },
    }));
  } catch { /* A failed cache write does not invalidate verified evidence. */ }
}
