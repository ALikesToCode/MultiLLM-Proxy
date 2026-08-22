const OPEN_THINK = "<think>";
const CLOSE_THINK = "</think>";
const MAX_PENDING_MARKUP_CHARACTERS = 64 * 1024;

function safeMetadataValue(value) {
  return String(value ?? "unknown")
    .replace(/[^A-Za-z0-9._:/-]/g, "?")
    .slice(0, 128);
}

function comparable(value) {
  return String(value ?? "")
    .replace(/<\/?think>/gi, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function cleanReasoning(value) {
  return String(value ?? "").replace(/<\/?think>/gi, "");
}

function longestExactOverlap(left, right) {
  const maximum = Math.min(left.length, right.length);
  for (let size = maximum; size >= 16; size -= 1) {
    if (left.slice(-size) === right.slice(0, size)) {
      return size;
    }
  }
  return 0;
}

function reasoningValues(source) {
  if (!source || typeof source !== "object") {
    return [];
  }

  const values = [];
  const seen = new Set();
  const push = (value) => {
    if (typeof value === "string" && value && !seen.has(value)) {
      seen.add(value);
      values.push(value);
    }
  };
  push(source.reasoning_content);
  push(source.reasoning);
  if (Array.isArray(source.reasoning_details)) {
    for (const detail of source.reasoning_details) {
      if (typeof detail === "string") {
        push(detail);
      } else if (detail && typeof detail === "object") {
        push(detail.text);
        push(detail.reasoning_content);
        push(detail.reasoning);
      }
    }
  }
  return values;
}

function deleteReasoningFields(target) {
  if (!target || typeof target !== "object") {
    return;
  }
  delete target.reasoning_content;
  delete target.reasoning;
  delete target.reasoning_details;
}

function nextThinkTag(value, fromIndex) {
  const lower = value.toLowerCase();
  const opening = lower.indexOf(OPEN_THINK, fromIndex);
  const closing = lower.indexOf(CLOSE_THINK, fromIndex);
  if (opening === -1 && closing === -1) {
    return null;
  }
  if (opening !== -1 && (closing === -1 || opening < closing)) {
    return { index: opening, tag: OPEN_THINK, opening: true };
  }
  return { index: closing, tag: CLOSE_THINK, opening: false };
}

function parseThinkMarkup(value, { flush = false } = {}) {
  const reasoning = [];
  const visible = [];
  let cursor = 0;
  let depth = 0;
  let sawTag = false;
  let sawClosing = false;

  while (cursor < value.length) {
    const tag = nextThinkTag(value, cursor);
    if (!tag) {
      const remainder = value.slice(cursor);
      if (depth > 0) {
        reasoning.push(remainder);
      } else {
        visible.push(remainder);
      }
      cursor = value.length;
      break;
    }

    const segment = value.slice(cursor, tag.index);
    if (depth > 0) {
      reasoning.push(segment);
    } else if (!tag.opening) {
      // A provider may replay plain analysis and terminate it with only a
      // closing tag. Treat the immediately preceding segment as reasoning.
      reasoning.push(segment);
    } else {
      visible.push(segment);
    }

    sawTag = true;
    if (tag.opening) {
      depth += 1;
    } else {
      sawClosing = true;
      depth = Math.max(0, depth - 1);
    }
    cursor = tag.index + tag.tag.length;
  }

  return {
    reasoning,
    visible: visible.join(""),
    sawTag,
    sawClosing,
    complete: depth === 0 || flush,
  };
}

function hasPossibleTagSuffix(value) {
  const lower = value.toLowerCase();
  const maximum = Math.min(CLOSE_THINK.length - 1, lower.length);
  for (let size = 1; size <= maximum; size += 1) {
    const suffix = lower.slice(-size);
    if (OPEN_THINK.startsWith(suffix) || CLOSE_THINK.startsWith(suffix)) {
      return true;
    }
  }
  return false;
}

function frameData(frame) {
  const data = frame
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trimStart())
    .join("\n")
    .trim();
  if (!data) {
    return null;
  }
  if (data === "[DONE]") {
    return { done: true };
  }
  try {
    return { done: false, payload: JSON.parse(data) };
  } catch {
    return null;
  }
}

function encodeFrame(payload) {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

function syntheticContentPayload(template, content) {
  const source = template && typeof template === "object" ? template : {};
  const firstChoice = Array.isArray(source.choices) ? source.choices[0] : null;
  return {
    ...source,
    choices: [
      {
        index: firstChoice?.index ?? 0,
        delta: { content },
        finish_reason: null,
      },
    ],
  };
}

function sanitizedPayload(payload, generatedContent) {
  const choices = Array.isArray(payload?.choices) ? [...payload.choices] : [];
  if (!choices.length) {
    return payload;
  }

  const first = choices[0] && typeof choices[0] === "object"
    ? { ...choices[0] }
    : {};
  const delta = first.delta && typeof first.delta === "object"
    ? { ...first.delta }
    : {};
  deleteReasoningFields(delta);
  if (generatedContent) {
    delta.content = generatedContent;
  } else {
    delete delta.content;
  }
  first.delta = delta;
  choices[0] = first;
  return { ...payload, choices };
}

function payloadHasSignal(payload) {
  const choice = payload?.choices?.[0];
  const delta = choice?.delta;
  return Boolean(
    choice?.finish_reason !== null && choice?.finish_reason !== undefined ||
      delta && Object.keys(delta).some((key) => key !== "role") ||
      payload?.usage,
  );
}

function createReasoningState(metadata) {
  const provider = safeMetadataValue(metadata?.provider);
  const model = safeMetadataValue(metadata?.model);
  return {
    provider,
    model,
    reasoningText: "",
    reasoningComparable: "",
    thinkOpen: false,
    thinkClosed: false,
    visibleStarted: false,
    pendingReasoningWhitespace: "",
    pendingContent: "",
    template: null,
  };
}

function appendReasoning(state, value, { replay = false } = {}) {
  if (state.thinkClosed || state.visibleStarted) {
    return "";
  }

  let candidate = cleanReasoning(value);
  const candidateComparable = comparable(candidate);
  if (!candidateComparable) {
    if (!replay && candidate) {
      if (state.thinkOpen) {
        state.reasoningText += candidate;
        return candidate;
      }
      state.pendingReasoningWhitespace += candidate;
    }
    return "";
  }
  // Explicit reasoning fields are token deltas, where repeated fragments are
  // meaningful. Historical de-duplication is only safe for replayed markup.
  if (
    replay &&
    state.reasoningComparable.includes(candidateComparable)
  ) {
    return "";
  }

  if (
    candidate.length > state.reasoningText.length &&
    candidate.startsWith(state.reasoningText)
  ) {
    candidate = candidate.slice(state.reasoningText.length);
  } else if (state.reasoningText) {
    const overlap = longestExactOverlap(state.reasoningText, candidate);
    candidate = candidate.slice(overlap);
  }
  if (!candidate.trim()) {
    return "";
  }

  candidate = state.pendingReasoningWhitespace + candidate;
  state.pendingReasoningWhitespace = "";

  state.reasoningText += candidate;
  state.reasoningComparable = comparable(state.reasoningText);
  if (!state.thinkOpen) {
    state.thinkOpen = true;
    return `<think>[provider: ${state.provider} | model: ${state.model}]\n${candidate}`;
  }
  return candidate;
}

function closeThinking(state) {
  if (!state.thinkOpen || state.thinkClosed) {
    return "";
  }
  state.thinkOpen = false;
  state.thinkClosed = true;
  return "</think>\n\n";
}

function looksLikeReasoningReplay(state, value) {
  if (!state.reasoningComparable) {
    return false;
  }
  const candidate = comparable(value).slice(0, 64);
  return candidate.length >= 24 && state.reasoningComparable.includes(candidate);
}

function consumePendingContent(state, { flush = false } = {}) {
  const value = state.pendingContent;
  if (!value) {
    return "";
  }

  const parsed = parseThinkMarkup(value, { flush });
  const containsMarkup = parsed.sawTag;
  if (
    !flush &&
    (containsMarkup && !parsed.complete || hasPossibleTagSuffix(value)) &&
    value.length < MAX_PENDING_MARKUP_CHARACTERS
  ) {
    return "";
  }
  if (
    !flush &&
    !containsMarkup &&
    looksLikeReasoningReplay(state, value) &&
    value.length < MAX_PENDING_MARKUP_CHARACTERS
  ) {
    return "";
  }

  state.pendingContent = "";
  let output = "";
  if (containsMarkup) {
    for (const part of parsed.reasoning) {
      output += appendReasoning(state, part, { replay: true });
    }
    const visible = state.visibleStarted
      ? parsed.visible
      : parsed.visible.replace(/^\s+/, "");
    if (visible) {
      output += closeThinking(state);
      state.visibleStarted = true;
      output += visible;
    } else if (parsed.sawClosing) {
      output += closeThinking(state);
    }
    return output;
  }

  let visible = value;
  const startsVisibleOutput = !state.visibleStarted;
  const followsThinking = Boolean(
    state.thinkOpen || state.thinkClosed || state.reasoningText,
  );
  if (looksLikeReasoningReplay(state, visible)) {
    const normalizedExisting = state.reasoningText.trim();
    if (normalizedExisting && visible.includes(normalizedExisting)) {
      visible = visible.slice(visible.indexOf(normalizedExisting) + normalizedExisting.length);
    } else {
      const overlap = longestExactOverlap(state.reasoningText, visible);
      visible = visible.slice(overlap);
    }
  }
  if (visible) {
    output += closeThinking(state);
    state.visibleStarted = true;
    output += startsVisibleOutput && followsThinking
      ? visible.replace(/^\s+/, "")
      : visible;
  }
  return output;
}

export function createRoleplayReasoningFrameNormalizer(metadata) {
  const state = createReasoningState(metadata);
  let done = false;

  return {
    transform(frame) {
      const parsed = frameData(frame);
      if (!parsed) {
        return [frame];
      }
      if (parsed.done) {
        const flushed = consumePendingContent(state, { flush: true }) + closeThinking(state);
        const frames = [];
        if (flushed) {
          frames.push(encodeFrame(syntheticContentPayload(state.template, flushed)));
        }
        frames.push("data: [DONE]\n\n");
        done = true;
        return frames;
      }

      const payload = parsed.payload;
      const choice = payload?.choices?.[0];
      const delta = choice?.delta;
      if (!choice || !delta || typeof delta !== "object") {
        return [frame];
      }
      state.template = payload;

      let generated = "";
      for (const value of reasoningValues(delta)) {
        generated += appendReasoning(state, value);
      }
      if (typeof delta.content === "string" && delta.content) {
        state.pendingContent += delta.content;
        generated += consumePendingContent(state);
      }
      if (choice.finish_reason !== null && choice.finish_reason !== undefined) {
        generated += consumePendingContent(state, { flush: true });
        generated += closeThinking(state);
      }

      const outputPayload = sanitizedPayload(payload, generated);
      return payloadHasSignal(outputPayload) ? [encodeFrame(outputPayload)] : [];
    },

    finish() {
      if (done) {
        return [];
      }
      const flushed = consumePendingContent(state, { flush: true }) + closeThinking(state);
      done = true;
      return flushed
        ? [encodeFrame(syntheticContentPayload(state.template, flushed))]
        : [];
    },
  };
}

export function createVisibleRoleplayContentCollector() {
  let pending = "";
  let depth = 0;

  const consume = (value, flush = false) => {
    pending += typeof value === "string" ? value : "";
    let output = "";
    let cursor = 0;
    while (cursor < pending.length) {
      const tag = nextThinkTag(pending, cursor);
      if (!tag) {
        const remainder = pending.slice(cursor);
        if (!flush && hasPossibleTagSuffix(remainder)) {
          pending = remainder;
          return output;
        }
        if (depth === 0) {
          output += remainder.replace(/<\/?think>/gi, "");
        }
        pending = "";
        return output;
      }

      const segment = pending.slice(cursor, tag.index);
      if (depth === 0) {
        output += segment;
      }
      if (tag.opening) {
        depth += 1;
      } else {
        depth = Math.max(0, depth - 1);
      }
      cursor = tag.index + tag.tag.length;
    }
    pending = "";
    return output;
  };

  return {
    consume(value) {
      return consume(value);
    },
    finish() {
      return consume("", true);
    },
  };
}

export function normalizeRoleplayCompletionPayload(payload, metadata) {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.choices)) {
    return { payload, changed: false, visibleContent: "" };
  }

  let changed = false;
  let visibleContent = "";
  const choices = payload.choices.map((choice, index) => {
    if (!choice?.message || typeof choice.message !== "object") {
      return choice;
    }
    const message = { ...choice.message };
    const content = typeof message.content === "string" ? message.content : "";
    const hasReasoning = reasoningValues(message).length > 0 || /<\/?think>/i.test(content);
    if (!hasReasoning) {
      if (index === 0) {
        visibleContent = content;
      }
      return choice;
    }

    const state = createReasoningState(metadata);
    let normalized = "";
    for (const value of reasoningValues(message)) {
      normalized += appendReasoning(state, value);
    }
    state.pendingContent = content;
    normalized += consumePendingContent(state, { flush: true });
    normalized += closeThinking(state);

    const collector = createVisibleRoleplayContentCollector();
    const visible = collector.consume(normalized) + collector.finish();
    if (index === 0) {
      visibleContent = visible.trimStart();
    }
    deleteReasoningFields(message);
    message.content = normalized;
    changed = true;
    return { ...choice, message };
  });

  return {
    payload: changed ? { ...payload, choices } : payload,
    changed,
    visibleContent,
  };
}
