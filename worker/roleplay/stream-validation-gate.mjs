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

function markerStart(value) {
  let lineStart = 0;
  while (lineStart <= value.length) {
    const line = value.slice(lineStart);
    const match = /^[\t ]*IMAGE PROMPT:/i.exec(line);
    if (match) {
      return lineStart;
    }
    const newline = value.indexOf("\n", lineStart);
    if (newline < 0) {
      return -1;
    }
    lineStart = newline + 1;
  }
  return -1;
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
    const boundary = markerStart(pending);
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

    const holdFrom = possibleMarkerLineStart(pending);
    const safe = pending.slice(0, holdFrom);
    pending = pending.slice(holdFrom);
    if (!safe) {
      return [];
    }
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
    },

    get releasedCharacters() {
      return released.length;
    },
  };
}
