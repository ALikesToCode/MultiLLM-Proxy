const IMAGE_PROMPT_MARKER = "IMAGE PROMPT:";

function framePayload(frame) {
  const data = String(frame ?? "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trimStart())
    .join("\n")
    .trim();
  if (!data || data === "[DONE]") {
    return null;
  }
  try {
    return JSON.parse(data);
  } catch {
    return null;
  }
}

function contentFrame(payload, content) {
  const choices = Array.isArray(payload?.choices)
    ? [...payload.choices]
    : [];
  if (!choices.length) {
    return "";
  }
  const choice = choices[0] && typeof choices[0] === "object"
    ? { ...choices[0] }
    : {};
  const delta = choice.delta && typeof choice.delta === "object"
    ? { ...choice.delta, content }
    : { content };
  choices[0] = { ...choice, delta };
  return `data: ${JSON.stringify({ ...payload, choices })}\n\n`;
}

function scanContent(value, initialDepth, initialLineStart) {
  let depth = initialDepth;
  let lineStart = initialLineStart;
  for (let index = 0; index < value.length; index += 1) {
    const tail = value.slice(index);
    const tag = /^<\/?think>/i.exec(tail);
    if (tag) {
      depth = tag[0][1] === "/" ? Math.max(0, depth - 1) : depth + 1;
      index += tag[0].length - 1;
      lineStart = false;
      continue;
    }
    if (depth === 0 && lineStart && /^[\t ]*IMAGE PROMPT:/i.test(tail)) {
      return { boundary: index, depth, lineStart };
    }
    lineStart = value[index] === "\n" ||
      (lineStart && /[\t ]/.test(value[index]));
  }
  return { boundary: -1, depth, lineStart };
}

function possibleThinkTagStart(value) {
  for (let size = Math.min(7, value.length); size > 0; size -= 1) {
    const suffix = value.slice(-size).toLowerCase();
    if ("<think>".startsWith(suffix) || "</think>".startsWith(suffix)) {
      return value.length - size;
    }
  }
  return value.length;
}

function possibleMarkerLineStart(value) {
  const lineStart = value.lastIndexOf("\n") + 1;
  const line = value.slice(lineStart);
  const candidate = line.replace(/^[\t ]*/, "").toUpperCase();
  return IMAGE_PROMPT_MARKER.startsWith(candidate)
    ? lineStart
    : value.length;
}

export function createRoleplayStreamValidationGate(enabled) {
  let pending = "";
  let released = "";
  let boundaryReached = false;
  let thinkingDepth = 0;
  let atLineStart = true;

  const releaseFromFrame = (frame) => {
    if (boundaryReached) {
      return [];
    }
    const payload = framePayload(frame);
    const content = payload?.choices?.[0]?.delta?.content;
    if (typeof content !== "string" || !content) {
      return [frame];
    }

    pending += content;
    const scanned = scanContent(pending, thinkingDepth, atLineStart);
    const boundary = scanned.boundary;
    if (boundary >= 0) {
      const safe = pending.slice(0, boundary);
      pending = pending.slice(boundary);
      boundaryReached = true;
      if (!safe) {
        return [];
      }
      released += safe;
      return [contentFrame(payload, safe)];
    }

    // Thinking can discuss the output schema without starting the final block.
    // Retain only ambiguous tag/marker prefixes, never the reasoning or story.
    const markerLine = pending.lastIndexOf("\n") + 1;
    const holdMarker = scanned.depth === 0 && (markerLine > 0 || atLineStart);
    const holdFrom = Math.min(
      holdMarker ? possibleMarkerLineStart(pending) : pending.length,
      possibleThinkTagStart(pending),
    );
    const safe = pending.slice(0, holdFrom);
    pending = pending.slice(holdFrom);
    if (!safe) {
      return [];
    }
    const next = scanContent(safe, thinkingDepth, atLineStart);
    thinkingDepth = next.depth;
    atLineStart = next.lineStart;
    released += safe;
    return [contentFrame(payload, safe)];
  };

  return {
    consume(frames, { hold = false } = {}) {
      if (!enabled) {
        return frames;
      }
      if (hold) {
        return [];
      }
      return frames.flatMap(releaseFromFrame).filter(Boolean);
    },

    remaining(cleanedContent) {
      const value = typeof cleanedContent === "string"
        ? cleanedContent
        : "";
      return value.startsWith(released)
        ? value.slice(released.length)
        : value;
    },

    discardLeg() {
      pending = "";
      released = "";
      boundaryReached = false;
      thinkingDepth = 0;
      atLineStart = true;
    },

    get releasedCharacters() {
      return released.length;
    },
  };
}
