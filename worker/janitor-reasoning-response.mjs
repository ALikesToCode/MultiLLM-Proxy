import { createRoleplayReasoningFrameNormalizer } from "./roleplay/reasoning-output.mjs";

const JANITOR_REASONING_HEADER = "janitor-glm";

function safeMetadataValue(value) {
  return String(value ?? "unknown")
    .replace(/[^A-Za-z0-9._:/-]/g, "?")
    .slice(0, 160);
}

function isJanitorOrigin(value) {
  if (!value) {
    return false;
  }
  try {
    const origin = new URL(value);
    return (
      origin.protocol === "https:" &&
      (origin.hostname === "janitorai.com" ||
        origin.hostname.endsWith(".janitorai.com"))
    );
  } catch {
    return false;
  }
}

function isEventStream(response) {
  return (
    response.body &&
    response.headers
      .get("content-type")
      ?.split(";", 1)[0]
      .trim()
      .toLowerCase() === "text/event-stream"
  );
}

function selectedModel(response) {
  return (
    response.headers.get("x-multillm-auto-selected-model") ||
    response.headers.get("x-multillm-model") ||
    ""
  );
}

function isGlm5Model(model) {
  return model.toLowerCase().includes("glm-5");
}

function providerModel(model, provider) {
  const prefix = `${provider}:`;
  return model.toLowerCase().startsWith(prefix.toLowerCase())
    ? model.slice(prefix.length)
    : model;
}

function splitSseFrames(value, flush = false) {
  const frames = [];
  let remaining = value;
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

function logStreamEvent(event, metadata, startedAt, firstDataAt, doneSeen) {
  const now = performance.now();
  console.log(
    JSON.stringify({
      event,
      provider: metadata.provider,
      model: metadata.model,
      ttfbMs: firstDataAt ? Math.max(0, Math.round(firstDataAt - startedAt)) : null,
      streamMs: Math.max(0, Math.round(now - startedAt)),
      doneSeen,
    }),
  );
}

function normalizedReasoningStream(
  upstreamBody,
  metadata,
  { requestSignal, startedAt },
) {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const normalizer = createRoleplayReasoningFrameNormalizer(metadata);
  let buffered = "";
  let firstDataAt = 0;
  let doneSeen = false;
  let settled = false;

  const record = (event) => {
    if (settled) {
      return;
    }
    settled = true;
    requestSignal?.removeEventListener?.("abort", onAbort);
    logStreamEvent(event, metadata, startedAt, firstDataAt, doneSeen);
  };
  const onAbort = () => record("janitor_glm_stream_aborted");
  requestSignal?.addEventListener?.("abort", onAbort, { once: true });

  const enqueue = (frame, controller) => {
    if (!firstDataAt && /^data:\s*(?!\[DONE\])/m.test(frame)) {
      firstDataAt = performance.now();
    }
    doneSeen ||= /^data:\s*\[DONE\]\s*$/m.test(frame);
    controller.enqueue(encoder.encode(frame));
  };

  const consume = (text, controller, flush = false) => {
    buffered += text;
    const split = splitSseFrames(buffered, flush);
    buffered = split.remaining;
    for (const frame of split.frames) {
      for (const normalized of normalizer.transform(frame)) {
        enqueue(normalized, controller);
      }
    }
  };

  return upstreamBody.pipeThrough(
    new TransformStream({
      transform(chunk, controller) {
        try {
          consume(decoder.decode(chunk, { stream: true }), controller);
        } catch (error) {
          record("janitor_glm_stream_error");
          throw error;
        }
      },
      flush(controller) {
        try {
          consume(decoder.decode(), controller, true);
          for (const frame of normalizer.finish()) {
            enqueue(frame, controller);
          }
          record("janitor_glm_stream_completed");
        } catch (error) {
          record("janitor_glm_stream_error");
          throw error;
        }
      },
    }),
  );
}

export function withJanitorGlmReasoningNormalization(
  request,
  response,
  { startedAt = performance.now() } = {},
) {
  const requestUrl = new URL(request.url);
  const model = selectedModel(response);
  if (
    request.method !== "POST" ||
    requestUrl.pathname !== "/v1/chat/completions" ||
    !isJanitorOrigin(request.headers.get("origin")) ||
    !response.ok ||
    !isEventStream(response) ||
    !isGlm5Model(model)
  ) {
    return response;
  }

  const provider = safeMetadataValue(
    response.headers.get("x-multillm-provider") ||
      model.split(":", 1)[0] ||
      "unknown",
  );
  const metadata = {
    provider,
    model: safeMetadataValue(providerModel(model, provider)),
  };
  console.log(
    JSON.stringify({
      event: "janitor_glm_reasoning_normalizer_applied",
      provider: metadata.provider,
      model: metadata.model,
    }),
  );

  const headers = new Headers(response.headers);
  headers.delete("content-length");
  headers.set("X-MultiLLM-Reasoning-Normalized", JANITOR_REASONING_HEADER);
  return new Response(
    normalizedReasoningStream(response.body, metadata, {
      requestSignal: request.signal,
      startedAt,
    }),
    {
      status: response.status,
      statusText: response.statusText,
      headers,
    },
  );
}
