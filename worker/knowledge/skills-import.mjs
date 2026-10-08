import { fail, fields, integer } from "./contracts.mjs";
import { digest } from "./evidence.mjs";
import { CLAWHUB, clawhubFile, directory, frontmatter, REF, repository, REVIEW_PATTERNS, reviewFlags } from "./skills-market.mjs";
import { pinOf } from "./skills-ledger.mjs";
import { skillId, skillKey, skillPath, slug } from "./skills-validation.mjs";

// Imports copy one reviewed skill folder, pinned to a GitHub commit or ClawHub version, into the
// "imported" root. A plan comes first; applying needs that exact pin and acceptance of each review flag.
export const IMPORT_FLAGS = [...REVIEW_PATTERNS.map(([flag]) => flag), "marketplace_suspicious"];
const SHA = /^[0-9a-f]{40}$/;
const VERSION = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/;
const FILE_LIMIT = 40;
const SKILL_BYTES = 128 * 1024;
const FILE_BYTES = 256 * 1024;
const TOTAL_BYTES = 5 * 1024 * 1024;
const LISTING_BYTES = 4 * 1024 * 1024;
const TIMEOUT_MS = 10000;
const CONCURRENCY = 6;
const DIFF_FILE_BYTES = 8 * 1024;
const DIFF_TOTAL_BYTES = 48 * 1024;
const DIFF_CELLS = 250000;
const USER_AGENT = "multillm-skills/1";

export function parseImport(payload) {
  fields(payload, ["repository", "path", "ref", "commit", "clawhub", "version", "accept_flags"]);
  const accept = payload.accept_flags ?? [];
  if (!Array.isArray(accept) || new Set(accept).size !== accept.length || accept.some(flag => !IMPORT_FLAGS.includes(flag))) {
    fail("invalid_request", "accept_flags lists review flags from the import plan.");
  }
  if (Object.hasOwn(payload, "clawhub")) {
    if (["repository", "path", "ref", "commit"].some(key => Object.hasOwn(payload, key))
      || typeof payload.clawhub !== "string" || !CLAWHUB.test(payload.clawhub)) fail("invalid_request", "Use a ClawHub owner/slug with an optional version.");
    if (payload.version !== undefined && (typeof payload.version !== "string" || !VERSION.test(payload.version))) fail("invalid_request", "Invalid version.");
    return { source: "clawhub", clawhub: payload.clawhub, version: payload.version, accept };
  }
  if (Object.hasOwn(payload, "version")) fail("invalid_request", "version applies to ClawHub imports.");
  if (!repository(payload.repository)) fail("invalid_request", "repository must be owner/name.");
  const folder = directory(payload.path);
  if (folder === null) fail("invalid_path", "path is the skill folder or its SKILL.md, relative to the repository.");
  if (payload.ref !== undefined && (typeof payload.ref !== "string" || !REF.test(payload.ref))) fail("invalid_request", "Invalid ref.");
  if (payload.commit !== undefined && (typeof payload.commit !== "string" || !SHA.test(payload.commit))) fail("invalid_request", "commit is a full 40-character SHA.");
  return { source: "github", repository: payload.repository, path: folder, ref: payload.ref ?? "HEAD", commit: payload.commit, accept };
}

export function parseReport(payload) {
  fields(payload, ["kind", "limit", "check"], ["kind"]);
  if (!["updates", "gaps"].includes(payload.kind)) fail("invalid_request", "kind is updates or gaps.");
  if (payload.check !== undefined && (typeof payload.check !== "boolean" || payload.kind !== "updates")) fail("invalid_request", "check applies to updates.");
  return { kind: payload.kind, limit: integer(payload.limit ?? 20, 1, 50, "limit"), check: payload.check === true };
}

const segments = path => path.split("/").map(encodeURIComponent).join("/");
const join = (folder, path) => folder ? `${folder}/${path}` : path;
const githubHeaders = env => ({ "User-Agent": USER_AGENT, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
  ...(env.GITHUB_TOKEN ? { Authorization: `Bearer ${env.GITHUB_TOKEN}` } : {}) });

// Raw bytes with manual redirects, a deadline and a size cap; upstream failures become stable codes.
async function get(url, headers, options, maxBytes) {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  options.signal?.addEventListener("abort", cancel, { once: true });
  const timer = setTimeout(cancel, options.importTimeoutMs ?? TIMEOUT_MS);
  try {
    let response;
    try { response = await (options.fetch ?? fetch)(url, { headers, redirect: "manual", signal: controller.signal }); }
    catch { fail(controller.signal.aborted ? "upstream_timeout" : "upstream_unavailable", "The skill source could not be reached.", controller.signal.aborted ? 504 : 502); }
    if (!response.ok) {
      await response.body?.cancel();
      if ([404, 422].includes(response.status)) fail("skill_missing", "The skill, ref or version was not found.", 404);
      if (response.status === 429 || (response.status === 403 && response.headers.get("x-ratelimit-remaining") === "0")) {
        fail("upstream_rate_limited", "The skill source rate-limited this request; retry later, or set GITHUB_TOKEN for GitHub.", 429);
      }
      fail("upstream_unavailable", `The skill source answered HTTP ${response.status}.`, 502);
    }
    if (Number(response.headers.get("content-length")) > maxBytes) { await response.body?.cancel(); fail("skill_limits", "A skill file or listing exceeds its size limit.", 413); }
    const chunks = [];
    let size = 0;
    const reader = response.body?.getReader();
    while (reader) {
      let next;
      try { next = await reader.read(); }
      catch { fail(controller.signal.aborted ? "upstream_timeout" : "upstream_unavailable", "The skill source stopped responding.", controller.signal.aborted ? 504 : 502); }
      if (next.done) break;
      size += next.value.byteLength;
      if (size > maxBytes) { await reader.cancel(); fail("skill_limits", "A skill file or listing exceeds its size limit.", 413); }
      chunks.push(next.value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return bytes;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", cancel);
  }
}
async function getJson(url, headers, options) {
  try { return JSON.parse(new TextDecoder().decode(await get(url, headers, options, LISTING_BYTES))); }
  catch (error) { if (error?.code) throw error; fail("upstream_unavailable", "The skill source returned invalid JSON.", 502); }
}

async function pool(items, worker) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, items.length) }, async () => {
    while (next < items.length) { const index = next++; results[index] = await worker(items[index]); }
  }));
  return results;
}

// SKILL.md first, then by path; files over a limit are skipped and listed, like the sync client.
async function download(entries, url, options) {
  const sorted = [...entries].sort((a, b) => (b.path === "SKILL.md") - (a.path === "SKILL.md") || a.path.localeCompare(b.path));
  if (sorted[0]?.path !== "SKILL.md") fail("skill_missing", "The folder has no SKILL.md.", 404);
  if (sorted[0].size > SKILL_BYTES) fail("skill_limits", "SKILL.md exceeds 128 KiB.", 413);
  const chosen = [], skipped = [];
  let total = 0;
  for (const entry of sorted) {
    let reason = null;
    try { skillPath(entry.path); } catch { reason = "invalid_path"; }
    reason ??= chosen.length >= FILE_LIMIT ? "file_limit" : entry.size > FILE_BYTES ? "too_large" : total + entry.size > TOTAL_BYTES ? "total_limit" : null;
    if (reason) skipped.push({ path: entry.path, reason });
    else { chosen.push(entry); total += entry.size; }
  }
  const files = await pool(chosen, async entry => {
    const bytes = await get(url(entry.path), { "User-Agent": USER_AGENT }, options, entry.path === "SKILL.md" ? SKILL_BYTES : FILE_BYTES);
    const sha256 = await digest(bytes);
    if (bytes.length !== entry.size || (entry.sha256 && entry.sha256 !== sha256)) fail("upstream_changed", `${entry.path} did not match the source listing.`, 502);
    return { path: entry.path, size: bytes.length, sha256, bytes };
  });
  return { files, skipped };
}

async function githubCommit(env, repositoryName, ref, options) {
  const commit = new TextDecoder().decode(await get(`https://api.github.com/repos/${repositoryName}/commits/${ref}`,
    { ...githubHeaders(env), Accept: "application/vnd.github.sha" }, options, 1024)).trim();
  if (!SHA.test(commit)) fail("upstream_unavailable", "GitHub returned no commit for that ref.", 502);
  return commit;
}
const githubTree = (env, origin, commit, recursive, options) => getJson(`https://api.github.com/repos/${origin.repository}/git/trees/${commit}${
  origin.path ? `:${segments(origin.path)}` : ""}${recursive ? "?recursive=1" : ""}`, githubHeaders(env), options);

async function githubSnapshot(env, request, options) {
  const commit = request.commit ?? await githubCommit(env, request.repository, request.ref, options);
  const tree = await githubTree(env, request, commit, true, options);
  if (tree?.truncated || !Array.isArray(tree?.tree)) fail("skill_limits", "The skill folder is too large to list.", 413);
  // Symlinks and submodules are not copied.
  const entries = tree.tree.filter(entry => entry?.type === "blob" && ["100644", "100755"].includes(entry.mode)
    && typeof entry.path === "string" && Number.isSafeInteger(entry.size)).map(({ path, size }) => ({ path, size }));
  const { files, skipped } = await download(entries, path =>
    `https://raw.githubusercontent.com/${request.repository}/${commit}/${segments(join(request.path, path))}`, options);
  return { pin: { source: "github", repository: request.repository, path: request.path, ref: request.ref, commit, tree: tree.sha },
    files, skipped, fallback: request.path.split("/").at(-1) || request.repository.split("/")[1] };
}

async function clawhubLatest(id, options) {
  const [owner, name] = id.split("/");
  const version = (await getJson(`https://clawhub.ai/api/v1/skills/${name}?owner=${owner}`, { "User-Agent": USER_AGENT }, options))?.latestVersion?.version;
  if (typeof version !== "string" || !VERSION.test(version)) fail("skill_missing", "ClawHub lists no version for that skill.", 404);
  return version;
}

async function clawhubSnapshot(request, options) {
  const [owner, name] = request.clawhub.split("/");
  const version = request.version ?? await clawhubLatest(request.clawhub, options);
  const detail = (await getJson(`https://clawhub.ai/api/v1/skills/${name}/versions/${encodeURIComponent(version)}?owner=${owner}`,
    { "User-Agent": USER_AGENT }, options))?.version;
  if (!Array.isArray(detail?.files)) fail("upstream_unavailable", "ClawHub returned no file list.", 502);
  // ClawHub's own scan verdict gates the import; its per-scanner opinions stay informational.
  const security = { status: typeof detail.security?.status === "string" ? detail.security.status.slice(0, 40) : "unknown",
    has_warnings: detail.security?.hasWarnings === true };
  if (security.status === "malicious") fail("skill_blocked", "ClawHub marks this version malicious.", 409);
  const entries = detail.files.filter(file => typeof file?.path === "string" && Number.isSafeInteger(file.size) && /^[a-f0-9]{64}$/.test(file.sha256 ?? ""))
    .map(({ path, size, sha256 }) => ({ path, size, sha256 }));
  const { files, skipped } = await download(entries, path => clawhubFile(request.clawhub, path, version), options);
  return { pin: { source: "clawhub", clawhub: request.clawhub, version }, files, skipped, security, fallback: name,
    extra: security.status === "clean" ? [] : ["marketplace_suspicious"] };
}

function review(snapshot) {
  const flagged = [];
  for (const file of snapshot.files) {
    try { file.text = new TextDecoder("utf-8", { fatal: true }).decode(file.bytes); } catch { continue; }
    const flags = reviewFlags(file.text);
    if (flags.length) flagged.push({ path: file.path, flags });
  }
  return { review_flags: [...new Set([...flagged.flatMap(item => item.flags), ...snapshot.extra ?? []])].sort(), flagged_files: flagged };
}

function base64(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  return btoa(binary);
}

const snapshotOf = (env, request, options) => request.source === "github" ? githubSnapshot(env, request, options) : clawhubSnapshot(request, options);
const applyPayload = pin => pin.source === "github" ? { repository: pin.repository, path: pin.path || "SKILL.md", ref: pin.ref, commit: pin.commit }
  : { clawhub: pin.clawhub, version: pin.version };

export async function importSkill(env, payload, store, options = {}) {
  const request = parseImport(payload);
  if (!store) fail("skills_unavailable", "Configure the Knowledge skills binding.", 503);
  const snapshot = await snapshotOf(env, request, options);
  const { review_flags, flagged_files } = review(snapshot);
  const skillMd = snapshot.files[0].text;
  if (skillMd === undefined) fail("invalid_skill", "SKILL.md must be UTF-8 text.");
  const meta = frontmatter(skillMd, 2000);
  const name = meta.name || snapshot.fallback;
  if (!meta.description) fail("invalid_skill", "SKILL.md needs a description in its frontmatter.");
  const id = skillId(slug(name).slice(0, 100));
  const skill = { root: "imported", skill_id: id, name: slug(name) === id ? name : id, description: meta.description,
    files: snapshot.files.map(file => ({ path: file.path, content_base64: base64(file.bytes), sha256: file.sha256 })) };
  const pinned = request.source === "github" ? Boolean(request.commit) : Boolean(request.version);
  const plan = { skill_id: id, name: skill.name, description: meta.description, origin: snapshot.pin,
    files: snapshot.files.map(({ path, size }) => ({ path, size })), skipped: snapshot.skipped, review_flags, flagged_files,
    ...(snapshot.security ? { marketplace_security: snapshot.security } : {}) };
  const accepted = request.accept.filter(flag => review_flags.includes(flag));
  if (pinned) {
    if (review_flags.includes("embedded_secret")) fail("secret_detected", "The skill contains a high-confidence secret and cannot be imported.", 422);
    const missing = review_flags.filter(flag => !request.accept.includes(flag));
    if (missing.length) fail("review_required", `Read the flagged files, then accept these review flags: ${missing.join(", ")}.`, 409);
  }
  const result = await store.call("import", { skill, origin: { ...snapshot.pin, accepted_flags: accepted }, dry_run: !pinned });
  if (result.status === "rejected") {
    if (result.reason === "skill_exists") {
      const from = result.origin ? ` (imported from ${result.origin.repository ?? `ClawHub ${result.origin.clawhub}`})` : "";
      fail("skill_exists", `The library already has ${id} in the ${result.root} root${from}; delete it first to replace it.`, 409);
    }
    if (result.reason === "secret_detected") fail("secret_detected", "The skill contains a high-confidence secret and cannot be imported.", 422);
    fail(result.reason ?? "invalid_skill", "The skill could not be imported.", 409);
  }
  if (!pinned) {
    return { status: "review", would_be: result.status, ...plan, apply: applyPayload(snapshot.pin),
      note: "Nothing was imported. Read flagged files with knowledge_skills_preview or at the source. Once the operator approves, call knowledge_skills_import with apply, plus accept_flags naming each review flag they accepted." };
  }
  return { status: result.status, ...plan, origin: { ...snapshot.pin, accepted_flags: accepted },
    note: "Imported skills are served by knowledge_skills_get as operator skills. Upstream changes are reported, never applied." };
}

// Line diff with shared prefix and suffix trimmed; an LCS covers bounded middles, otherwise the middle is replaced.
export function unifiedDiff(before, after, path, maxBytes) {
  // A final newline ends the last line; it is not an extra empty line.
  const split = text => text === "" ? [] : text.replace(/\n$/, "").split("\n");
  const a = split(before), b = split(after);
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length, endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }
  const middleA = a.slice(start, endA), middleB = b.slice(start, endB), ops = [];
  if (middleA.length * middleB.length <= DIFF_CELLS) {
    const width = middleB.length + 1, table = new Uint32Array((middleA.length + 1) * width);
    for (let i = middleA.length - 1; i >= 0; i--) for (let j = middleB.length - 1; j >= 0; j--) {
      table[i * width + j] = middleA[i] === middleB[j] ? table[(i + 1) * width + j + 1] + 1 : Math.max(table[(i + 1) * width + j], table[i * width + j + 1]);
    }
    let i = 0, j = 0;
    while (i < middleA.length || j < middleB.length) {
      if (i < middleA.length && j < middleB.length && middleA[i] === middleB[j]) { ops.push([" ", middleA[i++]]); j++; }
      else if (i < middleA.length && (j === middleB.length || table[(i + 1) * width + j] >= table[i * width + j + 1])) ops.push(["-", middleA[i++]]);
      else ops.push(["+", middleB[j++]]);
    }
  } else ops.push(...middleA.map(line => ["-", line]), ...middleB.map(line => ["+", line]));
  const all = [...a.slice(0, start).map(line => [" ", line]), ...ops, ...a.slice(endA).map(line => [" ", line])];
  // Changes up to six unchanged lines apart share a hunk with three lines of context.
  const groups = [];
  all.forEach(([op], index) => {
    if (op === " ") return;
    if (groups.length && index - groups.at(-1)[1] <= 7) groups.at(-1)[1] = index;
    else groups.push([index, index]);
  });
  const lines = [`--- a/${path}`, `+++ b/${path}`];
  let cursor = 0, oldLine = 0, newLine = 0;
  for (const [first, last] of groups) {
    const from = Math.max(0, first - 3), to = Math.min(all.length, last + 4);
    for (; cursor < from; cursor++) { if (all[cursor][0] !== "+") oldLine++; if (all[cursor][0] !== "-") newLine++; }
    const hunk = all.slice(from, to);
    const oldCount = hunk.filter(([op]) => op !== "+").length, newCount = hunk.filter(([op]) => op !== "-").length;
    lines.push(`@@ -${oldLine + (oldCount ? 1 : 0)},${oldCount} +${newLine + (newCount ? 1 : 0)},${newCount} @@`, ...hunk.map(([op, line]) => op + line));
  }
  const text = lines.join("\n");
  return text.length > maxBytes ? { text: text.slice(0, maxBytes), truncated: true } : { text, truncated: false };
}

async function stored(env, item, path) {
  try {
    const object = await env.KNOWLEDGE_SNAPSHOTS?.get(skillKey(item, path));
    return object ? new TextDecoder("utf-8", { fatal: true }).decode(await object.arrayBuffer()) : null;
  } catch { return null; }
}

async function changesFrom(env, item, snapshot) {
  const old = new Map(item.files.map(file => [file.path, file]));
  const skipped = new Set(snapshot.skipped.map(file => file.path));
  const changes = [];
  let budget = DIFF_TOTAL_BYTES;
  for (const file of snapshot.files) {
    const before = old.get(file.path);
    old.delete(file.path);
    if (before?.sha256 === file.sha256) continue;
    const change = { path: file.path, change: before ? "modified" : "added" };
    const previous = before ? await stored(env, item, file.path) : "";
    if (file.text !== undefined && previous !== null && budget > 0) {
      const diff = unifiedDiff(previous, file.text, file.path, Math.min(DIFF_FILE_BYTES, budget));
      change.diff = diff.text;
      if (diff.truncated) change.diff_truncated = true;
      budget -= diff.text.length;
    }
    changes.push(change);
  }
  for (const path of old.keys()) changes.push({ path, change: skipped.has(path) ? "skipped" : "removed" });
  return changes;
}

async function checkOne(env, item, options) {
  const origin = item.origin;
  let snapshot;
  if (origin.source === "github") {
    const commit = await githubCommit(env, origin.repository, origin.ref, options);
    if (commit === origin.commit) return { status: "current", latest: commit };
    // The repository moved on; the folder changed only if its tree did.
    if ((await githubTree(env, origin, commit, false, options))?.sha === origin.tree) return { status: "current", latest: commit };
    snapshot = await githubSnapshot(env, { ...origin, commit }, options);
  } else {
    const version = await clawhubLatest(origin.clawhub, options);
    if (version === origin.version) return { status: "current", latest: version };
    snapshot = await clawhubSnapshot({ clawhub: origin.clawhub, version }, options);
  }
  // Review decodes text files, which the diff needs.
  const { review_flags } = review(snapshot);
  const changes = await changesFrom(env, item, snapshot);
  if (!changes.length) return { status: "current", latest: pinOf(snapshot.pin) };
  return { status: "changed", latest: pinOf(snapshot.pin), changes, review_flags,
    apply: applyPayload(snapshot.pin),
    note: "Not applied. Review the diff; to adopt it, call knowledge_skills_import with apply and accept_flags." };
}

// Checks due imports one at a time; a failed check is recorded and retried after the next interval.
export async function checkImports(env, store, options = {}, { force = false, limit = 5 } = {}) {
  const due = await store.call("imports.due", { limit, force });
  for (const item of due) {
    let result;
    try { result = await checkOne(env, item, options); }
    catch (error) { result = { status: "error", error: error?.code ?? "upstream_unavailable" }; }
    await store.call("imports.checked", { skill_id: item.skill_id, pin: pinOf(item.origin), result });
  }
  return due.length;
}

export async function reportSkills(env, payload, store, options = {}) {
  const parsed = parseReport(payload);
  if (!store) fail("skills_unavailable", "Configure the Knowledge skills binding.", 503);
  // Two full snapshots fit the 55-second request deadline; the cron checks five at a time.
  const checked = parsed.check ? await checkImports(env, store, options, { force: true, limit: 2 }) : undefined;
  return { kind: parsed.kind, items: await store.call(`report.${parsed.kind}`, { limit: parsed.limit }), ...(checked === undefined ? {} : { checked }) };
}

