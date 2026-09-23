import { fail, MAX_SNAPSHOT_BYTES, publicUrl } from "./contracts.mjs";

const encoder = new TextEncoder();

export async function digest(value) {
  const hash = await crypto.subtle.digest("SHA-256", typeof value === "string" ? encoder.encode(value) : value);
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("");
}

export function normalizeSourceText(text) {
  if (typeof text !== "string" || !text.trim() || text.includes("\0")) fail("invalid_source", "The source did not return usable text.", 502);
  const normalized = text.replace(/\r\n?/g, "\n").trim();
  const bytes = encoder.encode(normalized);
  if (bytes.byteLength > MAX_SNAPSHOT_BYTES) fail("source_too_large", "The source exceeds the snapshot size limit.", 413);
  if (new TextDecoder("utf-8", { fatal: true }).decode(bytes) !== normalized) fail("invalid_source", "The source text is not valid Unicode.", 502);
  return normalized;
}

export function versionEvidence(url, target, source = {}) {
  if (!target || !/^\d+\.\d+(?:\.\d+)?(?:[-+][\w.-]+)?$/.test(target)) return { kind: "unknown" };
  const parsed = new URL(url);
  const official = { flask: ["flask.palletsprojects.com", "pallets/flask"], werkzeug: ["werkzeug.palletsprojects.com", "pallets/werkzeug"],
    python: ["docs.python.org", "python/cpython"], react: ["react.dev", "facebook/react"], nextjs: ["nextjs.org", "vercel/next.js"] }[source.product];
  const segments = parsed.pathname.split("/").filter(Boolean);
  const repository = segments.slice(0, 2).join("/");
  const github = ["github.com", "raw.githubusercontent.com"].includes(parsed.hostname);
  const identityKnown = source.identity_confirmed === true || (official && (github ? repository === official[1] : parsed.hostname === official[0]));
  if (!identityKnown) return { kind: "unknown" };
  const taggedRef = parsed.hostname === "github.com" && segments[2] === "blob" ? segments[3]
    : parsed.hostname === "raw.githubusercontent.com" ? segments[2] : null;
  const documentationVersion = segments[0] === "en" || segments[0] === "docs" ? segments[1] : segments[0];
  const locator = github ? taggedRef : documentationVersion;
  const exact = locator === target || locator === `v${target}`;
  return exact ? { kind: "exact", version: target, proof_url: url, basis: "versioned_source_url" } : { kind: "unknown" };
}

export async function createArtifact(source, rawText, provider, now = Date.now()) {
  const text = normalizeSourceText(rawText);
  const canonicalUrl = publicUrl(source.url);
  const contentHash = await digest(text);
  const id = await digest(`${source.id}\0${canonicalUrl}\0${contentHash}\0projection-1`);
  return { id, source_id: source.id, canonical_url: canonicalUrl, title: source.title || source.product || canonicalUrl,
    product: source.product || "", requested_version: source.version || "", version: versionEvidence(canonicalUrl, source.version, source),
    provider, content_hash: contentHash, snapshot_key: `snapshots/${id}.txt`, index_key: `revisions/${id}.txt`,
    fetched_at: new Date(now).toISOString(), checked_at: source.origin_checked === true ? new Date(now).toISOString() : null,
    expires_at: new Date(now + (source.retention_hours ?? 168) * 3600000).toISOString(),
    byte_length: encoder.encode(text).byteLength, status: "live", projection: 1 };
}

export function validateChunk(artifact, fullText, chunkText) {
  if (typeof fullText !== "string" || typeof chunkText !== "string" || !chunkText.trim()) return null;
  const start = fullText.indexOf(chunkText);
  if (start < 0) return null;
  const startByte = encoder.encode(fullText.slice(0, start)).length;
  return { artifact_id: artifact.id, source_id: artifact.source_id, text: chunkText,
    url: artifact.canonical_url, title: artifact.title, version: artifact.version, provider: artifact.provider,
    locator: { start_byte: startByte, end_byte: startByte + encoder.encode(chunkText).length },
    fetched_at: artifact.fetched_at, checked_at: artifact.checked_at, published_at: artifact.published_at ?? null,
    expires_at: artifact.expires_at, content_hash: artifact.content_hash };
}

export function evidenceMatch(artifact, request) {
  if (request.product && artifact.product !== request.product) return "unverified";
  if (!request.version) return "unspecified";
  return artifact.version?.kind === "exact" && artifact.version.version === request.version ? "exact" : "unverified";
}

export function selectPassage(text, query, maxCharacters = 2400) {
  if (text.length <= maxCharacters) return text;
  const words = query.toLowerCase().match(/[\p{L}\p{N}_]{3,}/gu) ?? [];
  const lower = text.toLowerCase();
  let bestStart = 0;
  let bestScore = -1;
  for (let start = 0; start < text.length; start += 800) {
    const span = lower.slice(start, start + maxCharacters);
    const score = words.reduce((count, word) => count + Number(span.includes(word)), 0);
    if (score > bestScore) { bestScore = score; bestStart = start; }
  }
  // Slice on code points to avoid introducing half-surrogates into citation text.
  if (bestStart && /[\uDC00-\uDFFF]/.test(text[bestStart])) bestStart -= 1;
  let end = Math.min(text.length, bestStart + maxCharacters);
  if (end < text.length && /[\uDC00-\uDFFF]/.test(text[end])) end -= 1;
  return text.slice(bestStart, end);
}

export function packEvidence(candidates, request) {
  const excerpts = [];
  const related = [];
  const seen = new Set();
  let estimate = 0;
  const ranked = [...candidates].sort((a, b) => Number(b.target_match === "exact") - Number(a.target_match === "exact")
    || (b.score ?? 0) - (a.score ?? 0));
  for (const candidate of ranked) {
    const key = `${candidate.artifact_id}:${candidate.locator.start_byte}:${candidate.locator.end_byte}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const remainingBytes = Math.max(0, (request.token_budget - estimate - 80) * 3);
    if (remainingBytes < 24) continue;
    let text = candidate.text;
    if (encoder.encode(text).length > remainingBytes) {
      let used = 0;
      text = Array.from(text).filter(character => {
        used += encoder.encode(character).length;
        return used <= remainingBytes;
      }).join("");
    }
    const cost = Math.ceil(encoder.encode(text).length / 3) + 80;
    estimate += cost;
    const { score, ...excerpt } = candidate;
    excerpt.text = text;
    excerpt.locator = { ...candidate.locator, end_byte: candidate.locator.start_byte + encoder.encode(text).length };
    (candidate.target_match === "unverified" ? related : excerpts).push(excerpt);
  }
  return { excerpts, related_evidence: related, token_count: estimate, token_counting_method: "estimated_utf8_bytes_divided_by_3_plus_citation_overhead" };
}
