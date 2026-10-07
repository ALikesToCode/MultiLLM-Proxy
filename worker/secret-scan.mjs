/** Bounded JSON-leaf secret detection, mirrored by services/secret_scan.py. */
import { secretDigest } from "./secret-digest.mjs";
import patterns from "./secret-patterns.json" with { type: "json" };

export const MAX_BYTES = 4_194_304;
const MAX_FINDINGS = 4096, MAX_NODES = 100_000, MAX_DEPTH = 64;
const PATTERNS = Object.entries(patterns).map(([type, pattern]) => [type, new RegExp(pattern, "g")]);
const KEY_MARKER = /-----(BEGIN|END) ([A-Z0-9 ]{0,32}PRIVATE KEY)-----/g;
const ASSIGN = /(?<![A-Za-z0-9_.-])["']?([A-Za-z_][A-Za-z0-9_.-]{0,127})["']?[ \t]*[=:][ \t]*["']?([^\s"',;}{]{12,4096})/g;
const FIELD = /KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH/i;
const EXAMPLE = /xxx|your_|example|placeholder|changeme|\*\*\*|REDACTED|dummy/i;
const UUID = /^[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$/;
const BINARY_FIELDS = new Set(["b64_json", "audio", "data", "image", "images"]);
const DATA_URL_PATTERN = String.raw`data:[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+;[A-Za-z0-9_.+=;-]*base64,[A-Za-z0-9+/= \t\r\n]+`;
const INTEGRITY_PATTERN = String.raw`(?<![A-Za-z0-9_-])sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}(?![A-Za-z0-9+/=_-])`;
const DATA_URL = new RegExp(`^(?:${DATA_URL_PATTERN})$(?![\\s\\S])`);
const INTEGRITY = new RegExp(`^(?:${INTEGRITY_PATTERN})$(?![\\s\\S])`);
const IGNORED_SPAN = new RegExp(`${DATA_URL_PATTERN}|${INTEGRITY_PATTERN}`, "g");
const encoder = new TextEncoder();
const empty = () => ({ high: 0, heuristic: 0, types: {}, paths: [], truncated: false });
function example(value) {
  const delimited = [["<", ">"], ["${", "}"], ["{{", "}}"]].some(([begin, end]) => {
    const start = value.indexOf(begin);
    return start >= 0 && value.indexOf(end, start + begin.length) >= 0;
  });
  return delimited || EXAMPLE.test(value) || UUID.test(value) || new Set(value).size < 2 || INTEGRITY.test(value);
}
function validDataUrl(value) {
  const header = value.slice(0, value.indexOf(",")).split(";");
  return header.at(-1) === "base64" && header.slice(1, -1).every(part => /^[A-Za-z0-9_.+-]+=[A-Za-z0-9_.+-]+$/.test(part));
}
const skipped = (value, field = "") => (DATA_URL.test(value) && validDataUrl(value))
  || (BINARY_FIELDS.has(field) && value.length >= 128 && /^[A-Za-z0-9+/=\r\n]+$/.test(value));

function heuristic(value) {
  const chars = Array.from(value);
  if (chars.length < 12 || example(value)) return false;
  const counts = new Map();
  for (const char of chars) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const n of counts.values()) entropy -= (n / chars.length) * Math.log2(n / chars.length);
  return entropy >= 3.0;
}

export function scanText(text) {
  if (typeof text !== "string") return [];
  text = text.slice(0, MAX_BYTES);
  const candidates = [];
  KEY_MARKER.lastIndex = 0;
  let match, pending = null;
  while ((match = KEY_MARKER.exec(text))) {
    if (match[1] === "BEGIN") pending = { start: match.index, label: match[2] };
    else if (pending?.label === match[2]) {
      if (!example(text.slice(pending.start, KEY_MARKER.lastIndex)))
        candidates.push({ start: pending.start, end: KEY_MARKER.lastIndex, type: "private_key", confidence: "high" });
      pending = null;
      if (candidates.length >= MAX_FINDINGS) break;
    }
  }
  for (const [type, pattern] of PATTERNS) {
    pattern.lastIndex = 0;
    while ((match = pattern.exec(text))) {
      if (!example(match[0])) candidates.push({ type, confidence: "high", start: match.index, end: pattern.lastIndex });
      if (candidates.length >= MAX_FINDINGS) break;
    }
    if (candidates.length >= MAX_FINDINGS) break;
  }
  ASSIGN.lastIndex = 0;
  while ((match = ASSIGN.exec(text))) {
    if (FIELD.test(match[1]) && heuristic(match[2])) candidates.push({ type: "secret_assignment", confidence: "heuristic",
      start: ASSIGN.lastIndex - match[2].length, end: ASSIGN.lastIndex });
    if (candidates.length >= MAX_FINDINGS) break;
  }
  const order = (a, b) => a.start - b.start || (a.confidence !== "high") - (b.confidence !== "high") || b.end - a.end;
  // Exclude contained candidates, never an entire pasted log by its prefix.
  IGNORED_SPAN.lastIndex = 0;
  const spans = (function* () {
    for (const match of text.matchAll(IGNORED_SPAN))
      if (!match[0].startsWith("data:") || validDataUrl(match[0])) yield match;
  })();
  let span = spans.next().value;
  const visible = [];
  for (const item of candidates.sort((a, b) => a.start - b.start)) {
    while (span && span.index + span[0].length <= item.start) span = spans.next().value;
    if (!span || item.start < span.index || item.end > span.index + span[0].length) visible.push(item);
  }
  const high = visible.filter(item => item.confidence === "high").sort(order);
  const selected = [];
  let lastEnd = -1;
  for (const item of high) if (item.start >= lastEnd) { selected.push(item); lastEnd = item.end; }
  let cursor = 0;
  for (const item of visible.filter(item => item.confidence === "heuristic").sort(order)) {
    while (cursor < selected.length && selected[cursor].end <= item.start) cursor += 1;
    if (cursor === selected.length || selected[cursor].start >= item.end) high.push(item);
  }
  const result = [];
  lastEnd = -1;
  for (const item of high.sort(order)) if (item.start >= lastEnd) { result.push(item); lastEnd = item.end; }
  if (!result.length) return [];
  // The public offsets count Unicode code points in both runtimes.
  let utf16 = 0, point = 0;
  const offsets = new Map(result.flatMap(item => [[item.start, 0], [item.end, 0]]));
  for (const char of text) {
    if (offsets.has(utf16)) offsets.set(utf16, point);
    utf16 += char.length; point += 1;
  }
  if (offsets.has(utf16)) offsets.set(utf16, point);
  return result.map(item => ({ ...item, start: offsets.get(item.start), end: offsets.get(item.end) }));
}

export function redactText(text, findings) {
  const chars = Array.from(text), parts = [];
  let position = 0;
  for (const finding of findings) {
    if (finding.confidence !== "high") continue;
    parts.push(chars.slice(position, finding.start).join(""));
    const secret = chars.slice(finding.start, finding.end).join("");
    const digest = secretDigest(secret);
    parts.push(`[REDACTED:${finding.type}:${digest}]`);
    position = finding.end;
  }
  parts.push(chars.slice(position).join(""));
  return parts.join("");
}

function walk(value, maxBytes, redact = false) {
  const report = empty();
  let remaining = Math.max(0, Math.trunc(maxBytes)), nodes = 0;
  function visit(item, path, field, depth) {
    nodes += 1;
    if (nodes > MAX_NODES || depth > MAX_DEPTH) { report.truncated = true; return item; }
    if (typeof item === "string") {
      if (skipped(item, field)) return item;
      let prefixEnd = Math.min(item.length, remaining);
      if (prefixEnd > 0 && /[\uD800-\uDBFF]/.test(item[prefixEnd - 1]) && /[\uDC00-\uDFFF]/.test(item[prefixEnd] ?? "")) prefixEnd -= 1;
      const bytes = encoder.encode(item.slice(0, prefixEnd));
      // A fatal decoder avoids inserting a replacement character at the budget boundary.
      let end = Math.min(remaining, bytes.length);
      while (end > 0 && end < bytes.length && (bytes[end] & 0xc0) === 0x80) end -= 1;
      const prefix = new TextDecoder().decode(bytes.subarray(0, end));
      remaining -= encoder.encode(prefix).length;
      if (prefix.length !== item.length) report.truncated = true;
      let findings = scanText(prefix);
      if (!findings.length && FIELD.test(field) && heuristic(prefix) && prefix === item) {
        findings = [{ type: "secret_field", confidence: "heuristic", start: 0, end: Array.from(prefix).length }];
      }
      for (const finding of findings) {
        report[finding.confidence] += 1;
        report.types[finding.type] = (report.types[finding.type] ?? 0) + 1;
      }
      if (findings.length && report.paths.length < 20) report.paths.push(path);
      if (findings.length >= MAX_FINDINGS) report.truncated = true;
      return redact && findings.length ? redactText(prefix, findings) + item.slice(prefix.length) : item;
    }
    if (item !== null && typeof item === "object") {
      let output = null;
      const array = Array.isArray(item);
      for (const key in item) {
        if (!Object.hasOwn(item, key)) continue;
        if (nodes >= MAX_NODES) { report.truncated = true; break; }
        const child = item[key];
        const updated = visit(child, `${path}[${array ? key : JSON.stringify(key)}]`, array ? field : key, depth + 1);
        if (updated !== child) {
          output ??= array ? item.slice() : { ...item };
          Object.defineProperty(output, key, { value: updated, writable: true, enumerable: true, configurable: true });
        }
      }
      return output ?? item;
    }
    return item;
  }
  return [visit(value, "$", "", 0), report];
}

export function scanPayload(value, { max_bytes = MAX_BYTES } = {}) { return walk(value, max_bytes)[1]; }
export function redactPayload(value, { mode } = {}) {
  if (!["off", "observe", "redact", "block"].includes(mode)) throw new TypeError("Unsupported secret scan mode");
  return mode === "off" ? [value, empty()] : walk(value, MAX_BYTES, mode === "redact");
}
