/** Deterministic metadata-only signals for explicit managed request boundaries. */
export const INJECTION_HEADER = "X-MultiLLM-Injection-Action";
export const MAX_INJECTION_BYTES = 1048576;
export const MAX_INJECTION_FINDINGS = 256;
const MAX_NODES = 8192;
const RANK = { off: 0, log: 1, block: 2 };
const warned = new Set();
// Fixed bounds on every repetition keep regex work linear in the bounded text.
const RULES = [
  ["instruction_override", "high", 3, /\b(?:ignore|disregard|override|forget)[ \t\r\n]{1,16}(?:all[ \t\r\n]{1,16})?(?:(?:previous|prior|above|system|developer)[ \t\r\n]{1,16}){1,2}(?:instructions|rules|prompts)\b/g],
  ["role_spoof", "high", 3, /<\|(?:im_start|start_header_id)\|>[ \t\r\n]{0,16}(?:system|developer)\b|<\/?(?:system|developer)>|\[inst\]|<<sys>>|```[ \t\r\n]{0,16}(?:system|developer)\b|\bsystem[ \t\r\n]{0,8}:[ \t\r\n]{0,8}override\b/g],
  ["secret_exfiltration", "high", 3, /\b(?:reveal|extract|exfiltrate|leak|print|send)[ \t\r\n]{1,16}(?:(?:the|your|all)[ \t\r\n]{1,16})?(?:system[ \t\r\n]{1,16}prompt|api[ _-]?keys?|passwords?|credentials|secrets|access[ _-]?tokens?)\b/g],
  ["jailbreak_mode", "medium", 2, /\b(?:developer|unrestricted|jailbreak)[ \t\r\n]{1,16}mode\b|\b(?:disable|bypass)[ \t\r\n]{1,16}(?:safety|guardrails|restrictions)\b/g],
];

function warnOnce(setting) {
  if (warned.has(setting)) return;
  warned.add(setting);
  console.warn(`Invalid ${setting}; prompt injection controls disabled`);
}

function threshold(value) {
  if (typeof value === "string" && /^[0-9]{1,3}$/.test(value.trim())) value = Number(value);
  return Number.isInteger(value) && value >= 1 && value <= MAX_INJECTION_FINDINGS * 3 ? value : null;
}

export function resolveInjectionPolicy(env = {}, { policies = [] } = {}) {
  const raw = env.PROMPT_INJECTION_MODE ?? "";
  let mode = typeof raw === "string" ? raw.trim().toLowerCase() : "invalid";
  if (!mode || mode === "off") return { mode: "off", threshold: 3 };
  if (!Object.hasOwn(RANK, mode)) { warnOnce("PROMPT_INJECTION_MODE"); return { mode: "off", threshold: 3 }; }
  const rawLimit = env.PROMPT_INJECTION_THRESHOLD ?? "";
  let limit = threshold(typeof rawLimit === "string" && !rawLimit.trim() ? "3" : rawLimit);
  if (limit === null) { warnOnce("PROMPT_INJECTION_THRESHOLD"); return { mode: "off", threshold: 3 }; }
  for (const policy of policies) {
    if (!policy || typeof policy !== "object" || Array.isArray(policy)) continue;
    if (typeof policy.mode === "string" && Object.hasOwn(RANK, policy.mode) && RANK[policy.mode] > RANK[mode]) mode = policy.mode;
    const tighter = threshold(policy.threshold);
    if (tighter !== null) limit = Math.min(limit, tighter);
  }
  return { mode, threshold: limit };
}

function normalize(text) {
  // Per-code-point normalization cannot reorder unbounded combining-mark runs.
  text = /[^\x00-\x7f]/.test(text)
    ? Array.from(text, char => char.normalize("NFKC").toLowerCase()).join("") : text.toLowerCase();
  return text.replace(
    /&#(?:x[0-9a-f]{1,6}|[0-9]{1,7});|&(?:lt|gt|amp|quot);|%[0-9a-f]{2}|\\u[0-9a-f]{4}/g,
    value => {
      if (["&lt;", "&gt;", "&amp;", "&quot;"].includes(value)) return { "&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": '"' }[value];
      const code = value.startsWith("&#x") ? Number.parseInt(value.slice(3, -1), 16)
        : value.startsWith("&#") ? Number(value.slice(2, -1))
          : Number.parseInt(value.slice(value.startsWith("%") ? 1 : 2), 16);
      return code < 128 ? String.fromCharCode(code) : value;
    },
  ).replace(/[\p{Cc}\p{Cf}]/gu, char => "\t\r\n".includes(char) ? char : "");
}

function* textNodes(payload, budget) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return;
  const stack = [[payload.messages, payload.contents, payload.input, payload.prompt][Symbol.iterator]()];
  while (stack.length) {
    const next = stack.at(-1).next();
    if (next.done) { stack.pop(); continue; }
    if (++budget.nodes > MAX_NODES) { budget.truncated = true; return; }
    const value = next.value;
    if (typeof value === "string") yield value;
    else if (Array.isArray(value)) stack.push(value[Symbol.iterator]());
    else if (value && typeof value === "object") {
      if (Object.hasOwn(value, "role") && !["user", "tool", "function"].includes(value.role)) continue;
      stack.push([value.content, value.text, value.parts, value.output][Symbol.iterator]());
    }
  }
}

export function evaluatePromptInjection(payload, env = {}, { policies = [], managed = true } = {}) {
  if (!managed) return { mode: "off", action: null, report: null };
  const policy = resolveInjectionPolicy(env, { policies });
  if (policy.mode === "off") return { mode: "off", action: null, report: null };
  const report = { rules: {}, severity: {}, count: 0, score: 0, scanned_bytes: 0, truncated: false };
  const budget = { nodes: 0, truncated: false }, encoder = new TextEncoder();
  for (const text of textNodes(payload, budget)) {
    const remaining = MAX_INJECTION_BYTES - report.scanned_bytes;
    // Slice before encoding; decoding drops an incomplete final UTF-8 character.
    let bytes = encoder.encode(text.slice(0, remaining));
    if (bytes.length > remaining || text.length > remaining) report.truncated = true;
    bytes = bytes.subarray(0, remaining);
    report.scanned_bytes += bytes.length;
    const normalized = normalize(new TextDecoder().decode(bytes, { stream: true }));
    for (const [rule, severity, score, pattern] of RULES) {
      pattern.lastIndex = 0;
      while (pattern.exec(normalized)) {
        report.rules[rule] = (report.rules[rule] ?? 0) + 1;
        report.severity[severity] = (report.severity[severity] ?? 0) + 1;
        report.count += 1; report.score += score;
        if (report.count === MAX_INJECTION_FINDINGS) break;
      }
      if (report.count === MAX_INJECTION_FINDINGS) break;
    }
    if (report.count === MAX_INJECTION_FINDINGS || report.scanned_bytes === MAX_INJECTION_BYTES) {
      report.truncated = true; break;
    }
  }
  report.truncated ||= budget.truncated;
  const action = report.score >= policy.threshold ? (policy.mode === "block" ? "blocked" : "logged") : null;
  return { mode: policy.mode, action, report };
}

export function applyInjectionHeader(headers, decision) {
  if (decision?.action) headers.set(INJECTION_HEADER, decision.action);
}

export async function recordPromptInjection(decision) {
  if (!decision?.action) return;
  const detail = { kind: "prompt_injection", mode: decision.mode, action: decision.action, ...decision.report };
  console.info("prompt_injection", detail);
}
