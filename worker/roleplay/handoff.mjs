// A fast first-pass model may hand a roleplay turn to a stronger one. Configured source models
// (ROLEPLAY_HANDOFF_FROM) receive an internal function; when one calls it instead of writing,
// the Worker discards that leg and the first available target (ROLEPLAY_HANDOFF_TO) writes the
// turn from the source's notes and draft. Clients never see the function or its call.

export const ROLEPLAY_HANDOFF_TOOL_NAME = "multillm_hand_off_turn";

const HANDOFF_REASONS = new Set(["deeper_reasoning", "stronger_prose"]);
const MAX_NOTES_CHARACTERS = 2_000;
const MAX_DRAFT_CHARACTERS = 32_000;
const MAX_ARGUMENT_CHARACTERS = 64_000;
const REASONING_EFFORTS_THAT_PREFER_TARGETS = new Set(["xhigh", "max"]);

export const ROLEPLAY_HANDOFF_TOOL = Object.freeze({
  type: "function",
  function: {
    name: ROLEPLAY_HANDOFF_TOOL_NAME,
    description: [
      "Pass this turn to a senior writer instead of answering it yourself.",
      "Call it only when the turn clearly needs more than you can deliver well:",
      "deeper_reasoning for tangled plot logic, many characters or factions to keep consistent,",
      "or a plan or mystery that must add up; stronger_prose for a pivotal scene such as a",
      "climax, a major reveal, a death or a turning point in a relationship.",
      "Most turns are ordinary: write those yourself and do not call this.",
      "Never call it for short, simple or out-of-character replies.",
    ].join(" "),
    parameters: {
      type: "object",
      properties: {
        reason: { type: "string", enum: ["deeper_reasoning", "stronger_prose"] },
        notes: {
          type: "string",
          description: "What the reply must achieve: key beats, tone and continuity facts, in under 80 words.",
        },
        draft: {
          type: "string",
          description: "Optional: your draft of the reply. The senior writer keeps what works and rewrites the rest.",
        },
      },
      required: ["reason", "notes"],
    },
  },
});

function entryKey(candidate) {
  return `${String(candidate?.provider ?? "").toLowerCase()}:${candidate?.model ?? ""}`;
}

export function isRoleplayHandoffSource(candidate, settings) {
  return Boolean(settings?.handoffTargets?.size && settings?.handoffSources?.has(entryKey(candidate)));
}

function isRoleplayHandoffTarget(candidate, settings) {
  return Boolean(settings?.handoffTargets?.has(entryKey(candidate)));
}

/** Later candidates a source may hand off to: the configured targets, in chain order. */
export function roleplayHandoffTargets(candidates, candidateIndex, settings) {
  if (!isRoleplayHandoffSource(candidates?.[candidateIndex], settings)) return [];
  return candidates
    .slice(candidateIndex + 1)
    .filter((candidate) => isRoleplayHandoffTarget(candidate, settings));
}

/** At most one handoff every `handoffMinTurns` turns per session; 0 or 1 lifts the cap. */
export function roleplayHandoffAllowed(state, settings) {
  const last = state?.lastHandoffTurn;
  if (!Number.isSafeInteger(last)) return true;
  return (state?.turns ?? 0) - last >= (settings?.handoffMinTurns ?? 0);
}

export function recordRoleplayHandoff(state) {
  return {
    ...state,
    lastHandoffTurn: state?.turns ?? 0,
    handoffs: (state?.handoffs ?? 0) + 1,
  };
}

// The tool stays on every source leg so the prompt prefix (and the provider's cache of it) does
// not change between turns; `tool_choice: "none"` withholds it when no handoff may happen.
export function injectRoleplayHandoffTool(payload, available) {
  if (!payload || !Array.isArray(payload.messages) || payload.tools !== undefined) {
    return payload;
  }
  return {
    ...payload,
    tools: [ROLEPLAY_HANDOFF_TOOL],
    tool_choice: available ? "auto" : "none",
  };
}

/** Callers asking for xhigh or max reasoning start on the targets instead of the sources. */
export function preferRoleplayHandoffTargets(candidates, parsed, settings) {
  const effort = parsed?.forwarded?.reasoning_effort;
  if (!REASONING_EFFORTS_THAT_PREFER_TARGETS.has(effort) || !settings?.handoffTargets?.size) {
    return candidates;
  }
  const firstSource = candidates.findIndex((candidate) => isRoleplayHandoffSource(candidate, settings));
  if (firstSource < 0) return candidates;
  const promoted = candidates
    .slice(firstSource)
    .filter((candidate) => isRoleplayHandoffTarget(candidate, settings));
  if (!promoted.length) return candidates;
  return [
    ...candidates.slice(0, firstSource),
    ...promoted,
    ...candidates.slice(firstSource).filter((candidate) => !promoted.includes(candidate)),
  ];
}

function clipped(value, limit) {
  return typeof value === "string" ? value.trim().slice(0, limit) : "";
}

export function roleplayHandoffCall(toolCalls) {
  const call = Array.isArray(toolCalls)
    ? toolCalls.find((entry) => entry?.function?.name === ROLEPLAY_HANDOFF_TOOL_NAME)
    : null;
  if (!call) return null;
  let args = {};
  try {
    const parsed = JSON.parse(call.function.arguments || "{}");
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) args = parsed;
  } catch {
    // A malformed call still asks for the handoff; it only loses its notes.
  }
  return {
    reason: HANDOFF_REASONS.has(args.reason) ? args.reason : "stronger_prose",
    notes: clipped(args.notes, MAX_NOTES_CHARACTERS),
    draft: clipped(args.draft, MAX_DRAFT_CHARACTERS),
  };
}

/** The target's prompt: the original turn plus a private note placed before the last user message. */
export function roleplayHandoffMessages(messages, handoff) {
  if (!Array.isArray(messages) || !handoff) return messages;
  const lines = [
    "[Private handoff note]",
    handoff.reason === "deeper_reasoning"
      ? "A first-pass writer passed the next turn to you because it needs careful reasoning: keep every character, plan and continuity fact consistent."
      : "A first-pass writer passed the next turn to you because it needs your strongest prose.",
    "Write the reply yourself and follow every roleplay instruction above. Never mention this note, the handoff or the draft.",
  ];
  if (handoff.notes) lines.push(`Their notes: ${handoff.notes}`);
  if (handoff.draft) {
    lines.push("Their draft of the reply follows. Keep what works, fix what does not, and rewrite freely:");
    lines.push(handoff.draft);
  }
  const next = [...messages];
  let insertionIndex = next.length;
  for (let index = next.length - 1; index >= 0; index -= 1) {
    if (next[index]?.role === "user") {
      insertionIndex = index;
      break;
    }
  }
  next.splice(insertionIndex, 0, { role: "system", content: lines.join("\n") });
  return next;
}

export function withoutRoleplayHandoffToolCalls(message) {
  if (!message || !Array.isArray(message.tool_calls)) return message;
  const remaining = message.tool_calls.filter(
    (call) => call?.function?.name !== ROLEPLAY_HANDOFF_TOOL_NAME,
  );
  if (remaining.length === message.tool_calls.length) return message;
  const next = { ...message };
  if (remaining.length) next.tool_calls = remaining;
  else delete next.tool_calls;
  return next;
}

/** A finished reply with no visible text and no caller tool call gave the reader nothing. */
export function isEmptyRoleplayReply({ assistant = "", finishReason = "", toolCalls = [], terminated = true } = {}) {
  if (!terminated || String(assistant).trim()) return false;
  const callerToolCalls = Array.isArray(toolCalls)
    ? toolCalls.filter((call) => call?.function?.name !== ROLEPLAY_HANDOFF_TOOL_NAME)
    : [];
  if (callerToolCalls.length) return false;
  return ["", "stop", "length", "eos", "end_turn", "tool_calls"].includes(String(finishReason).trim().toLowerCase());
}

function frameJson(frame) {
  const data = String(frame ?? "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trimStart())
    .join("\n")
    .trim();
  if (!data || data === "[DONE]") return null;
  try {
    return JSON.parse(data);
  } catch {
    return null;
  }
}

// Removes the handoff call from a source leg's frames before anything reaches the client. Later
// deltas of a call carry only its index, so the filter remembers which indexes are the handoff's.
export function createRoleplayHandoffFrameFilter() {
  let handoffIndexes = new Set();
  let otherToolCalls = false;

  const rewrite = (frame) => {
    if (typeof frame !== "string" || !frame.includes("tool_calls")) return [frame];
    const payload = frameJson(frame);
    const choice = payload?.choices?.[0];
    if (!choice) return [frame];
    const delta = choice.delta && typeof choice.delta === "object" ? { ...choice.delta } : null;
    let changed = false;
    if (delta && Array.isArray(delta.tool_calls)) {
      const kept = [];
      for (const call of delta.tool_calls) {
        const index = Number.isSafeInteger(call?.index) ? call.index : 0;
        if (call?.function?.name === ROLEPLAY_HANDOFF_TOOL_NAME) handoffIndexes.add(index);
        if (handoffIndexes.has(index)) {
          changed = true;
          continue;
        }
        otherToolCalls = true;
        kept.push(call);
      }
      if (kept.length) delta.tool_calls = kept;
      else delete delta.tool_calls;
    }
    let finishReason = choice.finish_reason;
    if (finishReason === "tool_calls" && handoffIndexes.size && !otherToolCalls) {
      finishReason = "stop";
      changed = true;
    }
    if (!changed) return [frame];
    const hasDelta = delta && Object.keys(delta).some((key) => key !== "role");
    if (!hasDelta && (finishReason === null || finishReason === undefined) && !payload.usage) return [];
    const choices = [...payload.choices];
    choices[0] = { ...choice, ...(delta ? { delta } : {}), finish_reason: finishReason ?? null };
    return [`data: ${JSON.stringify({ ...payload, choices })}\n\n`];
  };

  return {
    filter(frames) {
      return frames.flatMap(rewrite);
    },
    reset() {
      handoffIndexes = new Set();
      otherToolCalls = false;
    },
  };
}
