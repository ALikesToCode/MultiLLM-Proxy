import { fields, fail, integer, string } from "./contracts.mjs";
import { digest } from "./evidence.mjs";
import { scanText } from "../secret-scan.mjs";

// "imported" holds skills adopted from GitHub or ClawHub by an approved import; sync cannot write it.
export const SKILL_ROOTS = ["claude", "claude-library", "codex", "agents", "imported"];
export const SKILLS_LIMIT = 2000;
export const SYNC_REQUEST_BYTES = 8 * 1024 * 1024;
export const SYNC_BATCH_LIMIT = 16;
const encoder = new TextEncoder();
export const slug = name => name.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
export function skillId(value) {
  if (typeof value !== "string" || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value) || value.length > 100) fail("invalid_skill", "Invalid skill_id.");
  return value;
}
export function skillPath(value) {
  if (typeof value !== "string" || !value || value.length > 240 || /[\\\x00-\x1f\x7f:%?#]/.test(value)
    || value.split("/").some(part => !part || part === "." || part === "..") || value.startsWith("/")) fail("invalid_path", "Use a relative skill file path.");
  return value;
}
export function parseFind(payload) {
  fields(payload, ["query", "limit", "mode", "roots", "min_confidence"], ["query"]);
  const query = string(payload.query, 2000, "query");
  const mode = payload.mode ?? "hybrid";
  if (!["fast", "hybrid"].includes(mode)) fail("invalid_request", "Choose fast or hybrid mode.");
  if (payload.roots !== undefined && (!Array.isArray(payload.roots) || !payload.roots.length || payload.roots.length > SKILL_ROOTS.length
    || new Set(payload.roots).size !== payload.roots.length || payload.roots.some(root => !SKILL_ROOTS.includes(root)))) fail("invalid_request", "Invalid roots filter.");
  if (payload.min_confidence !== undefined && payload.min_confidence !== "high") fail("invalid_request", "Choose high min_confidence.");
  return { min_confidence: payload.min_confidence, query, limit: integer(payload.limit ?? 3, 1, 5, "limit"), mode, roots: payload.roots };
}
export function parseGet(payload) {
  fields(payload, ["skill_id", "path"], ["skill_id"]);
  return { skill_id: skillId(payload.skill_id), path: skillPath(payload.path ?? "SKILL.md") };
}
export function parseSync(payload) {
  fields(payload, ["skills", "delete", "dry_run"], ["skills"]);
  if (!Array.isArray(payload.skills) || payload.skills.length > SYNC_BATCH_LIMIT
    || payload.delete !== undefined && (!Array.isArray(payload.delete) || payload.delete.length > SKILLS_LIMIT)
    || payload.dry_run !== undefined && typeof payload.dry_run !== "boolean") fail("invalid_request", "Invalid sync batch.");
  const deletes = (payload.delete ?? []).map(skillId);
  const ids = payload.skills.map(skill => skillId(skill?.skill_id));
  if (new Set([...ids, ...deletes]).size !== ids.length + deletes.length) fail("invalid_request", "Duplicate sync identities.");
  return { skills: payload.skills, delete: deletes, dry_run: payload.dry_run ?? false };
}
function findings(text) { return [...new Set(scanText(text).filter(item => item.confidence === "high").map(item => item.type))]; }
export async function validateSkill(skill) {
  fields(skill, ["root", "skill_id", "name", "description", "files"], ["root", "skill_id", "name", "description", "files"]);
  const id = skillId(skill.skill_id), name = string(skill.name, 100, "name"), description = string(skill.description, 2000, "description");
  if (slug(name) !== id || !SKILL_ROOTS.includes(skill.root)) fail("invalid_skill", "Invalid skill name, slug or root.");
  if (!Array.isArray(skill.files) || !skill.files.length || skill.files.length > 40) fail("skill_limits", "A skill needs 1–40 files.");
  const metadataTypes = findings(`${name}: ${description}`);
  if (metadataTypes.length) return { rejected: { reason: "secret_detected", file: "SKILL.md", types: metadataTypes } };
  const files = [], seen = new Set();
  let size = 0, text = "";
  for (const file of skill.files) {
    fields(file, ["path", "content", "content_base64", "sha256"], ["path", "sha256"]);
    const path = skillPath(file.path);
    if (seen.has(path)) fail("invalid_skill", "Duplicate file path.");
    seen.add(path);
    if (Object.hasOwn(file, "content") === Object.hasOwn(file, "content_base64")) fail("invalid_skill", "Choose content or content_base64.");
    let bytes;
    if (Object.hasOwn(file, "content")) {
      if (typeof file.content !== "string" || file.content.length > 256 * 1024) fail("skill_limits", "File exceeds 256 KiB.");
      bytes = encoder.encode(file.content);
    } else {
      if (typeof file.content_base64 !== "string" || file.content_base64.length > 349528
        || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(file.content_base64)) fail("invalid_skill", "Invalid bounded base64 content.");
      bytes = Uint8Array.from(atob(file.content_base64), char => char.charCodeAt(0));
    }
    size += bytes.length;
    if (bytes.length > (path === "SKILL.md" ? 128 * 1024 : 256 * 1024) || size > 5 * 1024 * 1024) fail("skill_limits", "Skill file or total size exceeds its limit.");
    let decoded;
    try { decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
    catch { decoded = Array.from(bytes, byte => String.fromCharCode(byte)).join(""); }
    // Scan decoded bytes, including base64 uploads, before R2 or embeddings.
    const types = findings(`skill file\n${decoded}`);
    if (types.length) return { rejected: { reason: "secret_detected", file: path, types } };
    if (!/^[a-f0-9]{64}$/.test(file.sha256 ?? "") || await digest(bytes) !== file.sha256) fail("hash_mismatch", "File hash does not match its content.");
    if (path === "SKILL.md") {
      try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
      catch { fail("invalid_skill", "SKILL.md must be UTF-8 text."); }
    }
    files.push({ path, size: bytes.length, sha256: file.sha256, bytes });
  }
  if (!seen.has("SKILL.md")) fail("invalid_skill", "SKILL.md is required.");
  files.sort((a, b) => a.path.localeCompare(b.path));
  const manifest = files.map(({ path, size, sha256 }) => ({ path, size, sha256 }));
  const record = { skill_id: id, name, description, root: skill.root, files: manifest,
    content_hash: await digest(JSON.stringify([skill.root, name, description, manifest])),
    index_text: [...text.matchAll(/^#{1,6}\s+(.+)$/gm)].slice(0, 128).map(match => match[1]).join(" ").slice(0, 8000) + " " + text.slice(0, 2000) };
  return { record, files };
}
export const skillKey = (record, path) => `skills/${record.skill_id}/${record.content_hash}/${path}`;
