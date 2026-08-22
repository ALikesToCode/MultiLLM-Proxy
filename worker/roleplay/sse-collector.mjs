import {
  createRoleplayReasoningFrameNormalizer,
  createVisibleRoleplayContentCollector,
} from "./reasoning-output.mjs";

const MAX_COLLECTED_ASSISTANT_CHARACTERS = 1_000_000;

function splitSseFrames(text, flush = false) {
  const frames = [];
  let remaining = text;
  while (remaining) {
    const boundary = /\r?\n\r?\n/.exec(remaining);
    if (!boundary) {
      break;
    }
    const end = boundary.index + boundary[0].length;
    frames.push(remaining.slice(0, end));
    remaining = remaining.slice(end);
  }
  if (flush && remaining) {
    frames.push(remaining);
    remaining = "";
  }
  return { frames, remaining };
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
    return { done: false };
  }
}

function rewrittenChoiceFrame(payload, { finishReason, dropContent }) {
  const choices = Array.isArray(payload?.choices)
    ? [...payload.choices]
    : [];
  const original = choices[0] ?? {};
  const delta =
    original.delta && typeof original.delta === "object"
      ? { ...original.delta }
      : {};
  if (dropContent) {
    delete delta.content;
  }
  choices[0] = {
    ...original,
    delta,
    finish_reason: finishReason,
  };
  return `data: ${JSON.stringify({ ...payload, choices })}\n\n`;
}

function fallbackTemplate() {
  return {
    id: "chatcmpl-roleplay-repaired",
    object: "chat.completion.chunk",
    choices: [
      {
        index: 0,
        delta: {},
        finish_reason: null,
      },
    ],
  };
}

export function bufferedCompletionFrames(template, content, finishReason = "stop") {
  const source = template ?? fallbackTemplate();
  const contentFrame = rewrittenChoiceFrame(
    {
      ...source,
      choices: [
        {
          ...(source.choices?.[0] ?? {}),
          delta: { content },
          finish_reason: null,
        },
      ],
    },
    { finishReason: null, dropContent: false },
  );
  const terminalFrame = rewrittenChoiceFrame(source, {
    finishReason,
    dropContent: true,
  });
  return [contentFrame, terminalFrame, "data: [DONE]\n\n"];
}

export function createSseAssistantCollector({
  maximumCharacters = MAX_COLLECTED_ASSISTANT_CHARACTERS,
  deferTerminalFrames = false,
  reasoningMetadata = null,
} = {}) {
  let buffered = "";
  let assistant = "";
  let clientContent = "";
  let terminated = false;
  let finishReason = "";
  let withheld = [];
  let truncated = false;
  let template = null;
  const reasoningNormalizer = reasoningMetadata
    ? createRoleplayReasoningFrameNormalizer(reasoningMetadata)
    : null;
  const visibleCollector = reasoningMetadata
    ? createVisibleRoleplayContentCollector()
    : null;

  const appendBounded = (current, content) => {
    if (typeof content !== "string" || !content) {
      return current;
    }
    const remaining = maximumCharacters - current.length;
    if (remaining <= 0) {
      truncated = true;
      return current;
    }
    truncated ||= content.length > remaining;
    return current + content.slice(0, remaining);
  };

  const appendContent = (content) => {
    clientContent = appendBounded(clientContent, content);
    const visible = visibleCollector
      ? visibleCollector.consume(content)
      : content;
    assistant = appendBounded(assistant, visible);
  };

  const consumeFrame = (frame) => {
    const parsed = frameData(frame);
    if (!parsed) {
      return [frame];
    }
    if (parsed.done) {
      terminated = true;
      if (withheld.length) {
        withheld.push(frame);
        return [];
      }
      return [frame];
    }
    const choice = parsed.payload?.choices?.[0];
    if (!choice) {
      return [frame];
    }
    template = parsed.payload;
    appendContent(choice?.delta?.content);
    const terminal =
      typeof choice.finish_reason === "string"
        ? choice.finish_reason
        : "";
    if (!terminal) {
      return [frame];
    }
    finishReason = terminal;
    terminated = true;
    if (terminal !== "length" && !deferTerminalFrames) {
      return [frame];
    }

    if (typeof choice?.delta?.content === "string" && choice.delta.content) {
      withheld.push(
        rewrittenChoiceFrame(parsed.payload, {
          finishReason: terminal,
          dropContent: true,
        }),
      );
      return [
        rewrittenChoiceFrame(parsed.payload, {
          finishReason: null,
          dropContent: false,
        }),
      ];
    }
    withheld.push(frame);
    return [];
  };

  const consumeBuffered = (text, flush = false) => {
    buffered += text;
    const split = splitSseFrames(buffered, flush);
    buffered = split.remaining;
    const frames = reasoningNormalizer
      ? split.frames.flatMap((frame) => reasoningNormalizer.transform(frame))
      : split.frames;
    return frames.flatMap(consumeFrame);
  };

  return {
    consume(text) {
      return consumeBuffered(text);
    },
    finish(text = "") {
      const output = consumeBuffered(text, true);
      if (reasoningNormalizer) {
        output.push(...reasoningNormalizer.finish().flatMap(consumeFrame));
      }
      if (visibleCollector) {
        assistant = appendBounded(assistant, visibleCollector.finish());
      }
      return {
        assistant,
        clientContent,
        finishReason,
        terminated,
        truncated,
        template,
        output,
        withheld: [...withheld],
      };
    },
  };
}
