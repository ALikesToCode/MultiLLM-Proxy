/** Batch content stays in the existing media bucket; D1 holds only ownership and pointers. */
import { boundedBytes } from "./media-outbound.mjs";

export const MAX_FILE_BYTES = 10 * 1024 * 1024;
export const MAX_RESULT_BYTES = 1024 * 1024;
export const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
export const ENDPOINTS = new Set(["/v1/chat/completions", "/v1/responses"]);
export const record = value => value !== null && typeof value === "object" && !Array.isArray(value);
export const newId = prefix => `${prefix}_${crypto.randomUUID().replaceAll("-", "")}`;
export const reply = (body, status = 200) => Response.json({ version: 1, ...body },
  { status, headers: { "cache-control": "no-store" } });
export function failure(code, message, status = 400, line) {
  return reply({ error: { code, message, ...(line ? { line } : {}) } }, status);
}
export function batchFlag(env, name) {
  const value = String(env[name] ?? "").trim().toLowerCase();
  if (["", "false", "0", "no", "off"].includes(value)) return false;
  if (["true", "1", "yes", "on"].includes(value)) return true;
  if (!warned.has(name)) { warned.add(name); console.warn(JSON.stringify({ event: "invalid_batch_setting", setting: name })); }
  return false;
}
const warned = new Set();

export function validateJsonl(bytes) {
  const bad = (line, message) => { const error = Error(message); error.line = line; throw error; };
  if (bytes.byteLength > MAX_FILE_BYTES) bad(1, "Batch input exceeds 10 MiB.");
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { bad(1, "Batch input must be UTF-8 JSONL."); }
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (!lines.length) bad(1, "Batch input is empty.");
  const items = [], seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    if (i >= 1000) bad(i + 1, "Batch input exceeds 1,000 lines.");
    let item;
    try { item = JSON.parse(lines[i]); } catch { bad(i + 1, "Invalid JSON object."); }
    if (!record(item) || typeof item.custom_id !== "string" || !/^[^\x00-\x1f\x7f]{1,64}$/.test(item.custom_id)
      || seen.has(item.custom_id) || item.method !== "POST" || !ENDPOINTS.has(item.url) || !record(item.body)
      || typeof item.body.model !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$/.test(item.body.model)
      || (item.body.stream !== undefined && item.body.stream !== false)) bad(i + 1, "Invalid batch item or duplicate custom_id.");
    for (const name of ["max_tokens", "max_completion_tokens", "max_output_tokens"]) {
      if (item.body[name] !== undefined && (!Number.isSafeInteger(item.body[name]) || item.body[name] < 1
        || item.body[name] > 262144)) bad(i + 1, "Output token limit must be between 1 and 262144.");
    }
    if (item.body.n !== undefined && (!Number.isSafeInteger(item.body.n) || item.body.n < 1 || item.body.n > 16)) bad(i + 1, "Completion count must be between 1 and 16.");
    seen.add(item.custom_id); items.push(item);
  }
  return items;
}

export function fileObject(row) {
  return { id: row.id, object: "file", bytes: row.bytes, created_at: row.created_at,
    filename: row.filename, purpose: row.purpose, status: "processed", status_details: null };
}
export const ownedFile = (db, owner, id) => db.prepare("SELECT * FROM gateway_batch_files WHERE owner=? AND id=?").bind(owner, id).first();

export async function storeFile(env, owner, filename, content, purpose, now, id = newId("file")) {
  const key = `batches/files/${id}`;
  const size = new TextEncoder().encode(content).byteLength;
  await env.multillm_media.put(key, content, { httpMetadata: { contentType: "application/jsonl" } });
  await env.INTELLIGENCE_DB.prepare(`INSERT INTO gateway_batch_files
    (id,owner,filename,purpose,bytes,r2_key,created_at) VALUES (?,?,?,?,?,?,?)`)
    .bind(id, owner, filename, purpose, size, key, now).run();
  return fileObject({ id, bytes: size, created_at: now, filename, purpose });
}

export async function inputItems(env, file) {
  const object = await env.multillm_media.get(file.r2_key);
  if (!object) throw Error("batch_input_missing");
  return validateJsonl(new Uint8Array(await object.arrayBuffer()));
}

export async function handleFileOperation(body, env, now) {
  const db = env.INTELLIGENCE_DB;
  if (body.operation === "file_create") {
    if (typeof body.filename !== "string" || body.filename.length > 255 || typeof body.content !== "string"
      || body.content.length > Math.ceil(MAX_FILE_BYTES / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(body.content)) {
      return failure("invalid_file", "Send a bounded JSONL file.");
    }
    let bytes, items;
    try { bytes = Uint8Array.from(atob(body.content), c => c.charCodeAt(0)); items = validateJsonl(bytes); }
    catch (error) { return failure("invalid_file", error.line ? error.message : "Invalid file encoding.", 400, error.line ?? 1); }
    // Preserve the uploaded bytes exactly, including whitespace and CRLF.
    return reply({ file: await storeFile(env, body.owner, body.filename || "input.jsonl",
      new TextDecoder().decode(bytes), "batch", now), item_count: items.length });
  }
  if (body.operation === "file_list") {
    const rows = await db.prepare("SELECT * FROM gateway_batch_files WHERE owner=? AND id>? ORDER BY id LIMIT ?")
      .bind(body.owner, body.after ?? "", pageLimit(body.limit) + 1).all();
    return reply(listObject(rows.results.map(fileObject), pageLimit(body.limit)));
  }
  const file = await ownedFile(db, body.owner, body.id ?? "");
  if (!file) return failure("not_found", "File not found.", 404);
  if (body.operation === "file_get") return reply({ file: fileObject(file) });
  if (body.operation === "file_content") {
    const object = await env.multillm_media.get(file.r2_key);
    if (!object) throw Error("batch_file_missing");
    const bytes = new Uint8Array(await object.arrayBuffer());
    let text = "";
    for (let start = 0; start < bytes.length; start += 8192) text += String.fromCharCode(...bytes.subarray(start, start + 8192));
    return reply({ content: btoa(text) });
  }
  if (body.operation === "file_delete") {
    const active = await db.prepare(`SELECT id FROM gateway_batches WHERE input_file_id=?
      AND status IN ('validating','in_progress','finalizing','cancelling') LIMIT 1`).bind(file.id).first();
    if (active) return failure("file_in_use", "An active batch still uses this file.", 409);
    await env.multillm_media.delete(file.r2_key);
    await db.prepare("DELETE FROM gateway_batch_files WHERE id=? AND owner=?").bind(file.id, body.owner).run();
    return reply({ id: file.id, object: "file", deleted: true });
  }
  return failure("invalid_operation", "Unknown file operation.");
}
export const pageLimit = value => Number.isSafeInteger(value) && value >= 1 && value <= 100 ? value : 20;
export function listObject(data, limit) {
  const page = data.slice(0, limit);
  return { object: "list", data: page, first_id: page[0]?.id ?? null, last_id: page.at(-1)?.id ?? null, has_more: data.length > limit };
}
export async function readBatchBody(request) {
  const bytes = await boundedBytes(request, 16 * 1024 * 1024);
  if (!bytes) return null;
  try { const body = JSON.parse(new TextDecoder().decode(bytes)); return record(body) ? body : null; }
  catch { return null; }
}
