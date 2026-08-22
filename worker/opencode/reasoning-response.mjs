import {
  createRoleplayReasoningFrameNormalizer,
  normalizeRoleplayCompletionPayload,
} from "../roleplay/reasoning-output.mjs";

const OPENCODE_NATIVE_CHAT_PATH = "/opencode/v1/chat/completions";
const SSE_FRAME_BOUNDARY = /\r?\n\r?\n/;

function normalizedPathname(pathname) {
  return String(pathname ?? "")
    .replace(/\/{2,}/g, "/")
    .toLowerCase();
}

function normalizedModel(value) {
  let model = typeof value === "string" ? value.trim() : "";
  if (model.toLowerCase().startsWith("opencode:")) {
    model = model.slice("opencode:".length);
  } else if (model.toLowerCase().startsWith("opencode-go/")) {
    model = model.slice("opencode-go/".length);
  }
  return model || "unknown";
}

function responseHeaders(source, metadata, bodyChanged) {
  const headers = new Headers(source);
  headers.set("X-MultiLLM-Provider", "opencode");
  headers.set("X-MultiLLM-Model", normalizedModel(metadata?.model));
  if (bodyChanged) {
    for (const header of [
      "Content-Encoding",
      "Content-Length",
      "Content-MD5",
      "Digest",
      "ETag",
      "Transfer-Encoding",
    ]) {
      headers.delete(header);
    }
  }
  return headers;
}

function responseWithBody(response, body, metadata, bodyChanged) {
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders(response.headers, metadata, bodyChanged),
  });
}

function enqueueFrames(controller, encoder, frames) {
  for (const frame of frames) {
    if (frame) {
      controller.enqueue(encoder.encode(frame));
    }
  }
}

function createNormalizedSseBody(upstreamBody, metadata) {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const normalizer = createRoleplayReasoningFrameNormalizer(metadata);
  let buffered = "";

  const drainCompleteFrames = (controller) => {
    while (buffered) {
      const boundary = SSE_FRAME_BOUNDARY.exec(buffered);
      if (!boundary) {
        return;
      }
      const frameEnd = boundary.index + boundary[0].length;
      const frame = buffered.slice(0, frameEnd);
      buffered = buffered.slice(frameEnd);
      enqueueFrames(controller, encoder, normalizer.transform(frame));
    }
  };

  return upstreamBody.pipeThrough(
    new TransformStream({
      transform(chunk, controller) {
        buffered += decoder.decode(chunk, { stream: true });
        drainCompleteFrames(controller);
      },
      flush(controller) {
        buffered += decoder.decode();
        drainCompleteFrames(controller);
        if (buffered) {
          enqueueFrames(controller, encoder, normalizer.transform(buffered));
          buffered = "";
        }
        enqueueFrames(controller, encoder, normalizer.finish());
      },
    }),
  );
}

export function isNativeOpencodeChatRequest(pathname, method) {
  return (
    String(method ?? "GET").toUpperCase() === "POST" &&
    normalizedPathname(pathname) === OPENCODE_NATIVE_CHAT_PATH
  );
}

export async function resolveOpencodeChatMetadata(request, pathname) {
  if (!isNativeOpencodeChatRequest(pathname, request?.method)) {
    return null;
  }

  let model = "unknown";
  try {
    const payload = await request.clone().json();
    model = normalizedModel(payload?.model);
  } catch {
    // Invalid JSON remains the upstream's responsibility. The normalizer can
    // still label a reasoning response with an explicit unknown model.
  }
  return { provider: "opencode", model };
}

export async function normalizeOpencodeChatResponse(response, metadata) {
  if (!metadata) {
    return response;
  }

  const contentType = response.headers.get("Content-Type")?.toLowerCase() ?? "";
  if (contentType.includes("text/event-stream") && response.body) {
    return responseWithBody(
      response,
      createNormalizedSseBody(response.body, metadata),
      metadata,
      true,
    );
  }

  if (!contentType.includes("application/json")) {
    return responseWithBody(response, response.body, metadata, false);
  }

  const originalBytes = await response.arrayBuffer();
  let responseBody = originalBytes;
  let bodyChanged = false;
  try {
    const payload = JSON.parse(new TextDecoder().decode(originalBytes));
    const normalized = normalizeRoleplayCompletionPayload(payload, metadata);
    if (normalized.changed) {
      responseBody = JSON.stringify(normalized.payload);
      bodyChanged = true;
    }
  } catch {
    // Preserve invalid or non-OpenAI JSON bodies byte-for-byte.
  }
  return responseWithBody(
    response,
    responseBody,
    metadata,
    bodyChanged,
  );
}
