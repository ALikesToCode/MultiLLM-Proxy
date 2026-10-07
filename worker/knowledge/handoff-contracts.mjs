import { fail, fields, integer, validId } from "./contracts.mjs";

export const HANDOFF_BYTES = 32 * 1024;
export const HANDOFF_RENDER_BYTES = 4500;
export const HANDOFF_OPERATIONS = ["handoffs.save", "handoffs.get", "handoffs.list", "handoffs.delete"];
const encoder = new TextEncoder();
export const handoffBytes = value => encoder.encode(JSON.stringify(value)).byteLength;

function text(value, maximum, name, required = false) {
  if (typeof value !== "string" || Array.from(value).length > maximum || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)
    || required && !value.trim()) fail("invalid_request", `${name} must be a string of at most ${maximum} characters.`);
  return value;
}

export function handoffSections(value) {
  const counts = { files: 100, decisions: 30, failed_attempts: 30, commands: 30, next_steps: 30, open_questions: 20 };
  fields(value, ["goal", "state", ...Object.keys(counts)]);
  const result = { goal: text(value.goal === undefined ? "" : value.goal, 500, "goal"), state: text(value.state === undefined ? "" : value.state, 500, "state") };
  for (const [name, maximum] of Object.entries(counts)) {
    const items = value[name] === undefined ? [] : value[name];
    if (!Array.isArray(items) || items.length > maximum) fail("invalid_request", `${name} accepts at most ${maximum} items.`);
    result[name] = items.map(item => {
      if (!["files", "commands"].includes(name)) return text(item, 500, name);
      const keys = name === "files" ? ["path", "change"] : ["command", "outcome"];
      fields(item, keys, keys);
      return Object.fromEntries(keys.map(key => [key, text(item[key], 500, key)]));
    });
  }
  return result;
}

export function parseHandoff(operation, payload) {
  if (operation === "save") {
    fields(payload, ["project", "branch", "title", "summary", "sections", "source", "ttl_days"], ["project", "title", "sections", "source"]);
    fields(payload.source, ["agent", "thread_id"], ["agent"]);
    if (!["claude", "codex", "opencode", "other"].includes(payload.source.agent)) fail("invalid_request", "Invalid source agent.");
    const source = { agent: payload.source.agent };
    if (payload.source.thread_id !== undefined) source.thread_id = text(payload.source.thread_id, 200, "thread_id");
    return { project: text(payload.project, 200, "project", true), branch: text(payload.branch === undefined ? "" : payload.branch, 200, "branch"),
      title: text(payload.title, 200, "title"), summary: text(payload.summary === undefined ? "" : payload.summary, 4000, "summary"),
      sections: handoffSections(payload.sections), source, ttl_days: integer(payload.ttl_days === undefined ? 14 : payload.ttl_days, 1, 90, "ttl_days") };
  }
  if (operation === "get") {
    fields(payload, ["project", "branch", "id"]);
    if (payload.project === undefined && payload.id === undefined) fail("invalid_request", "project or id is required.");
    return { ...(payload.project === undefined ? {} : { project: text(payload.project, 200, "project", true) }), ...(payload.branch === undefined ? {} : { branch: text(payload.branch, 200, "branch") }),
      ...(payload.id === undefined ? {} : { id: handoffId(payload.id) }) };
  }
  if (operation === "list") {
    fields(payload, ["project", "limit"]);
    return { ...(payload.project === undefined ? {} : { project: text(payload.project, 200, "project", true) }),
      limit: integer(payload.limit === undefined ? 20 : payload.limit, 1, 20, "limit") };
  }
  if (operation === "delete") { fields(payload, ["id"], ["id"]); return { id: handoffId(payload.id) }; }
  fail("unknown_operation", "Unknown handoff operation.", 404);
}

export function handoffId(id) {
  if (!validId(id)) fail("invalid_request", "Invalid handoff identifier.");
  return id;
}

export function renderHandoff(record) {
  const { sections: s } = record;
  const lines = [`# ${record.title}`, `${record.project}${record.branch ? ` (${record.branch})` : ""} · ${record.source.agent} · ${record.created_at}`,
    `Goal: ${s.goal}`, `State: ${s.state}`];
  for (const [name, items] of [["Next steps", s.next_steps], ["Open questions", s.open_questions],
    ["Files", s.files.map(item => `${item.path}: ${item.change}`)], ["Decisions", s.decisions],
    ["Failed attempts", s.failed_attempts], ["Commands", s.commands.map(item => `${item.command}: ${item.outcome}`)]]) {
    if (items.length) lines.push(`\n${name}:`, ...items.map(item => `- ${item}`));
  }
  if (record.summary) lines.push(`\nSummary: ${record.summary}`);
  const bytes = encoder.encode(lines.join("\n"));
  if (bytes.length <= HANDOFF_RENDER_BYTES) return new TextDecoder().decode(bytes);
  // Match retrieval’s UTF-8/3 estimate without cutting a Unicode code point.
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(0, HANDOFF_RENDER_BYTES - 4)).replace(/\uFFFD$/, "") + "\n…";
}
