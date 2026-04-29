import { Container, getContainer, switchPort } from "@cloudflare/containers";

const API_ROUTE_PREFIXES = new Set([
  "azure",
  "cerebras",
  "chutes",
  "gemini",
  "gemma",
  "googleai",
  "groq",
  "hyperbolic",
  "nineteen",
  "openai",
  "opencode",
  "openrouter",
  "palm",
  "sambanova",
  "scaleway",
  "together",
  "v1",
  "xai",
]);
const CORS_ALLOWED_METHODS = "GET, POST, PUT, DELETE, PATCH, OPTIONS";
const CORS_DEFAULT_HEADERS = "Authorization, Content-Type, Accept, Origin, X-Requested-With";
const OPENCODE_BASE_URL = "https://opencode.ai/zen/go/v1";
const UPSTREAM_HEADER_WHITELIST = new Set([
  "accept",
  "accept-language",
  "content-type",
  "http-referer",
  "openai-organization",
  "user-agent",
  "x-request-id",
  "x-title",
]);

const DIRECT_ENV_KEYS = [
  "ADMIN_USERNAME",
  "ADMIN_API_KEY",
  "AUTH_DB_PATH",
  "FLASK_SECRET_KEY",
  "JWT_SECRET",
  "PROJECT_ID",
  "LOCATION",
  "GOOGLE_ENDPOINT",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GOOGLE_APPLICATION_CREDENTIALS_JSON",
  "OPENAI_API_KEY",
  "CEREBRAS_API_KEY",
  "XAI_API_KEY",
  "TOGETHER_API_KEY",
  "AZURE_API_KEY",
  "SCALEWAY_API_KEY",
  "HYPERBOLIC_API_KEY",
  "SAMBANOVA_API_KEY",
  "OPENROUTER_API_KEY",
  "OPENCODE_API_KEY",
  "OPENROUTER_SITE_URL",
  "OPENROUTER_APP_NAME",
  "OPENROUTER_REFERER",
  "PALM_API_KEY",
  "NINETEEN_API_KEY",
  "CHUTES_API_TOKEN",
  "GEMINI_API_KEY",
  "APP_NAME",
  "GUNICORN_WORKERS",
  "GUNICORN_THREADS",
  "GUNICORN_TIMEOUT",
];

const DYNAMIC_ENV_PATTERNS = [/^GROQ_API_KEY_\d+$/];

function shouldPassThroughKey(key) {
  return DIRECT_ENV_KEYS.includes(key) || DYNAMIC_ENV_PATTERNS.some((pattern) => pattern.test(key));
}

function collectContainerEnv(source = {}) {
  const envVars = {
    AUTH_DB_PATH: source.AUTH_DB_PATH ?? "/tmp/auth.sqlite3",
    FLASK_ENV: source.FLASK_ENV ?? "production",
    HOME: "/tmp",
    SERVER_HOST: "0.0.0.0",
    SERVER_PORT: "8080",
    PYTHONUNBUFFERED: "1",
  };

  for (const [key, value] of Object.entries(source)) {
    if (!shouldPassThroughKey(key)) {
      continue;
    }

    if (value === undefined || value === null || value === "") {
      continue;
    }

    envVars[key] = String(value);
  }

  return envVars;
}

function isApiRequestPath(pathname) {
  const stripped = pathname.replace(/^\/+|\/+$/g, "");
  if (!stripped) {
    return false;
  }

  if (stripped === "health") {
    return true;
  }

  const [firstSegment] = stripped.split("/", 1);
  return API_ROUTE_PREFIXES.has(firstSegment);
}

function isDirectHealthPath(pathname) {
  return pathname === "/health";
}

function isDirectOpencodePath(pathname) {
  return pathname === "/opencode" || pathname.startsWith("/opencode/");
}

function extractBearerToken(request) {
  const authHeader = request.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return "";
  }
  return authHeader.slice("Bearer ".length).trim();
}

function jsonResponse(body, init = {}) {
  const headers = new Headers(init.headers);
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  return new Response(JSON.stringify(body), {
    ...init,
    headers,
  });
}

function buildFallbackHealthResponse() {
  return jsonResponse({
    status: "healthy",
    mode: "worker-fallback",
  });
}

function buildRootFallbackResponse() {
  return new Response(
    `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>MultiLLM Proxy</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 0; background: #0b1020; color: #e5e7eb; }
      main { max-width: 48rem; margin: 0 auto; padding: 4rem 1.5rem; }
      h1 { margin: 0 0 1rem; font-size: 2rem; }
      p { line-height: 1.6; color: #cbd5e1; }
      code { background: #111827; padding: 0.15rem 0.35rem; border-radius: 0.35rem; }
      a { color: #93c5fd; }
    </style>
  </head>
  <body>
    <main>
      <h1>MultiLLM Proxy</h1>
      <p>The dashboard container is currently unavailable, but the worker fallback is live.</p>
      <p>Use <code>/health</code> for status checks and <code>/opencode/chat/completions</code> for the Janitor AI-compatible proxy path.</p>
    </main>
  </body>
</html>`,
    {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=UTF-8",
      },
    },
  );
}

function buildUnauthorizedResponse() {
  return jsonResponse(
    {
      error: "Authentication required",
      message: "Please provide a valid admin API key in the Authorization header.",
    },
    { status: 401 },
  );
}

function buildMissingUpstreamKeyResponse() {
  return jsonResponse(
    {
      error: "Server configuration error",
      message: "OPENCODE_API_KEY is not configured on the worker.",
    },
    { status: 500 },
  );
}

function buildOpencodeUpstreamUrl(requestUrl) {
  const upstreamUrl = new URL(OPENCODE_BASE_URL);
  const suffix = requestUrl.pathname.replace(/^\/opencode/, "");
  upstreamUrl.pathname = `${upstreamUrl.pathname.replace(/\/$/, "")}${suffix || ""}`;
  upstreamUrl.search = requestUrl.search;
  return upstreamUrl;
}

function buildUpstreamHeaders(request, upstreamToken) {
  const headers = new Headers();

  for (const [header, value] of request.headers.entries()) {
    if (UPSTREAM_HEADER_WHITELIST.has(header.toLowerCase())) {
      headers.set(header, value);
    }
  }

  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }

  headers.set("Authorization", `Bearer ${upstreamToken}`);
  return headers;
}

function copyProxyResponseHeaders(headers) {
  const responseHeaders = new Headers();

  for (const [header, value] of headers.entries()) {
    const normalized = header.toLowerCase();
    if (normalized === "content-length" || normalized === "content-encoding" || normalized === "transfer-encoding") {
      continue;
    }
    responseHeaders.set(header, value);
  }

  return responseHeaders;
}

function looksLikeMeaningfulStreamText(text) {
  if (!text) {
    return false;
  }

  let alnumChars = 0;
  let asciiWordChars = 0;
  for (const char of text) {
    if (/[0-9A-Za-z]/.test(char)) {
      asciiWordChars += 1;
    }
    if (/\p{L}|\p{N}/u.test(char)) {
      alnumChars += 1;
    }
  }

  return alnumChars > 0 && asciiWordChars >= 4;
}

function stripThinkBlocks(value, { trimEdges = true } = {}) {
  if (typeof value !== "string") {
    return "";
  }

  let remaining = value;
  let stripped = "";

  while (remaining) {
    const lowerRemaining = remaining.toLowerCase();
    const openingIndex = lowerRemaining.indexOf("<think>");
    const closingIndex = lowerRemaining.indexOf("</think>");

    if (openingIndex === -1) {
      stripped += remaining.replace(/<\/think>/gi, "");
      break;
    }

    if (closingIndex !== -1 && closingIndex < openingIndex) {
      stripped += remaining.slice(0, closingIndex);
      remaining = remaining.slice(closingIndex + "</think>".length);
      continue;
    }

    stripped += remaining.slice(0, openingIndex);
    remaining = remaining.slice(openingIndex + "<think>".length);

    const innerClosingIndex = remaining.toLowerCase().indexOf("</think>");
    if (innerClosingIndex === -1) {
      break;
    }

    remaining = remaining.slice(innerClosingIndex + "</think>".length);
  }

  return trimEdges ? stripped.trim() : stripped;
}

function sanitizeReasoningCandidate(value, { trimEdges = false } = {}) {
  if (typeof value !== "string") {
    return "";
  }

  let sanitized = value.replace(/<\/?think>/gi, "");
  const strippedEmbeddedPayload = stripEmbeddedStreamChunkPayload(sanitized);
  if (strippedEmbeddedPayload !== null) {
    sanitized = strippedEmbeddedPayload;
  }

  return trimEdges ? sanitized.trim() : sanitized;
}

function extractReasoningPreview(source, { trimEdges = true } = {}) {
  if (!source || typeof source !== "object") {
    return "";
  }

  const parts = [];
  const seen = new Set();
  const maybePush = (value) => {
    const sanitized = sanitizeReasoningCandidate(value, { trimEdges });
    if (!sanitized || seen.has(sanitized)) {
      return;
    }
    seen.add(sanitized);
    parts.push(sanitized);
  };

  maybePush(source.reasoning_content);
  maybePush(source.reasoning);

  if (Array.isArray(source.reasoning_details)) {
    for (const detail of source.reasoning_details) {
      if (typeof detail === "string") {
        maybePush(detail);
        continue;
      }

      if (detail && typeof detail === "object") {
        maybePush(detail.text);
        maybePush(detail.reasoning);
        maybePush(detail.reasoning_content);
      }
    }
  }

  return parts.join("");
}

function formatVisibleThinkBlock(reasoningPreview, content = "") {
  const normalizedPreview = sanitizeReasoningCandidate(reasoningPreview, { trimEdges: true });
  const normalizedContent = stripThinkBlocks(content);
  if (!normalizedPreview) {
    return normalizedContent;
  }

  return `<think>${normalizedPreview}</think>${normalizedContent ? `\n\n${normalizedContent}` : ""}`;
}

function flushVisibleThinkingBuffer(state) {
  if (!state || !Array.isArray(state.thinkingBuffer) || state.thinkingBuffer.length === 0) {
    return "";
  }

  const combinedPreview = state.thinkingBuffer.join("");
  state.thinkingBuffer = [];
  state.thinkingBufferedChars = 0;

  if (!combinedPreview) {
    return "";
  }

  let output = "";
  if (!state.thinkingOpen) {
    output += buildStreamingChunk("<think>");
    state.thinkingOpen = true;
  }

  output += buildStreamingChunk(combinedPreview);
  return output;
}

function appendVisibleThinkingChunk(reasoningPreview, state) {
  const normalizedPreview = sanitizeReasoningCandidate(reasoningPreview);
  if (!normalizedPreview || !state || state.thinkingClosed) {
    return "";
  }

  state.thinkingBuffer.push(normalizedPreview);
  state.thinkingBufferedChars += normalizedPreview.length;

  if (/[.!?…]$/.test(normalizedPreview) || state.thinkingBufferedChars >= 160) {
    return flushVisibleThinkingBuffer(state);
  }

  return "";
}

function closeVisibleThinkingChunk(state) {
  if (!state || state.thinkingClosed) {
    return "";
  }

  let output = flushVisibleThinkingBuffer(state);
  if (!state.thinkingOpen) {
    if (!output) {
      return "";
    }

    state.thinkingOpen = true;
  }

  state.thinkingOpen = false;
  state.thinkingClosed = true;
  output += buildStreamingChunk("</think>\n\n");
  return output;
}

function extractTaggedReasoningContent(chunk, insideReasoningBlock) {
  let remaining = chunk;
  const reasoningParts = [];
  const contentParts = [];

  if (insideReasoningBlock) {
    const closingIndex = remaining.toLowerCase().indexOf("</think>");
    if (closingIndex === -1) {
      reasoningParts.push(remaining);
      return {
        contentChunk: "",
        reasoningChunk: reasoningParts.join(""),
        insideReasoningBlock: true,
      };
    }

    reasoningParts.push(remaining.slice(0, closingIndex));
    remaining = remaining.slice(closingIndex + "</think>".length);
    insideReasoningBlock = false;
  }

  while (true) {
    const openingIndex = remaining.toLowerCase().indexOf("<think>");
    if (openingIndex === -1) {
      contentParts.push(remaining);
      break;
    }

    contentParts.push(remaining.slice(0, openingIndex));
    remaining = remaining.slice(openingIndex + "<think>".length);
    const closingIndex = remaining.toLowerCase().indexOf("</think>");

    if (closingIndex === -1) {
      reasoningParts.push(remaining);
      insideReasoningBlock = true;
      remaining = "";
      break;
    }

    reasoningParts.push(remaining.slice(0, closingIndex));
    remaining = remaining.slice(closingIndex + "</think>".length);
  }

  return {
    contentChunk: contentParts.join("").trim(),
    reasoningChunk: reasoningParts.join(""),
    insideReasoningBlock,
  };
}

function stripEmbeddedStreamChunkPayload(chunk) {
  if (!chunk || chunk.startsWith("data: ")) {
    return null;
  }

  let cleanedChunk = chunk;
  let strippedAnyPayload = false;
  const marker = '"chat.completion.chunk"';

  while (true) {
    const markerIndex = cleanedChunk.indexOf(marker);
    if (markerIndex === -1) {
      break;
    }

    const objectStart = cleanedChunk.lastIndexOf("{", markerIndex);
    if (objectStart === -1) {
      break;
    }

    let depth = 0;
    let inString = false;
    let escapeNext = false;
    let objectEnd = null;

    for (let index = objectStart; index < cleanedChunk.length; index += 1) {
      const char = cleanedChunk[index];

      if (escapeNext) {
        escapeNext = false;
        continue;
      }

      if (char === "\\") {
        escapeNext = true;
        continue;
      }

      if (char === '"') {
        inString = !inString;
        continue;
      }

      if (inString) {
        continue;
      }

      if (char === "{") {
        depth += 1;
      } else if (char === "}") {
        depth -= 1;
        if (depth === 0) {
          objectEnd = index + 1;
          break;
        }
      }
    }

    if (objectEnd === null) {
      break;
    }

    let parsedPayload;
    try {
      parsedPayload = JSON.parse(cleanedChunk.slice(objectStart, objectEnd));
    } catch {
      break;
    }

    if (!parsedPayload || typeof parsedPayload !== "object" || parsedPayload.object !== "chat.completion.chunk") {
      break;
    }

    cleanedChunk = `${cleanedChunk.slice(0, objectStart)}${cleanedChunk.slice(objectEnd)}`.trim();
    strippedAnyPayload = true;
  }

  if (!strippedAnyPayload) {
    return null;
  }

  if (looksLikeMeaningfulStreamText(cleanedChunk)) {
    return cleanedChunk;
  }

  return "";
}

function buildStreamingChunk(content) {
  return `data: ${JSON.stringify({
    id: crypto.randomUUID(),
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: "opencode-stream",
    choices: [{ delta: { content } }],
  })}\n\n`;
}

function sanitizeOpenAiStreamingPayload(payload) {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.choices)) {
    return payload;
  }

  const sanitizedChoices = [];

  for (const choice of payload.choices) {
    if (!choice || typeof choice !== "object") {
      continue;
    }

    const sanitizedChoice = { ...choice };

    if (sanitizedChoice.delta && typeof sanitizedChoice.delta === "object") {
      const sanitizedDelta = { ...sanitizedChoice.delta };
      delete sanitizedDelta.reasoning;
      delete sanitizedDelta.reasoning_details;

      if (typeof sanitizedDelta.content === "string") {
        sanitizedDelta.content = stripThinkBlocks(sanitizedDelta.content, { trimEdges: false });
      }

      if (sanitizedDelta.content === "") {
        delete sanitizedDelta.content;
      }

      const hasMeaningfulDelta = Object.keys(sanitizedDelta).some(
        (key) => !["role"].includes(key),
      );

      if (!hasMeaningfulDelta) {
        continue;
      }

      sanitizedChoice.delta = sanitizedDelta;
    }

    sanitizedChoices.push(sanitizedChoice);
  }

  if (sanitizedChoices.length === 0) {
    return null;
  }

  return {
    ...payload,
    choices: sanitizedChoices,
  };
}

function sanitizeOpenAiCompletionPayload(payload) {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.choices)) {
    return payload;
  }

  return {
    ...payload,
    choices: payload.choices.map((choice) => {
      if (!choice || typeof choice !== "object") {
        return choice;
      }

      const sanitizedChoice = { ...choice };
      if (sanitizedChoice.message && typeof sanitizedChoice.message === "object") {
        const sanitizedMessage = { ...sanitizedChoice.message };
        const reasoningPreview = extractReasoningPreview(sanitizedMessage);
        delete sanitizedMessage.reasoning;
        delete sanitizedMessage.reasoning_details;
        sanitizedMessage.content = formatVisibleThinkBlock(reasoningPreview, sanitizedMessage.content);
        sanitizedChoice.message = sanitizedMessage;
      }
      return sanitizedChoice;
    }),
  };
}

function payloadHasVisibleContent(payload) {
  return Array.isArray(payload?.choices) && payload.choices.some((choice) => {
    const delta = choice?.delta;
    return Boolean(typeof delta?.content === "string" && delta.content.length > 0);
  });
}

function standardizeOpencodeStreamingChunk(chunk, state) {
  const strippedChunk = chunk.trim();
  if (!strippedChunk || strippedChunk.startsWith(":")) {
    return "";
  }

  const dataPayload = chunk.startsWith("data: ") ? chunk.slice(6).trim() : strippedChunk;
  if (dataPayload === "[DONE]") {
    return `${closeVisibleThinkingChunk(state)}data: [DONE]\n\n`;
  }

  if (chunk.startsWith("data: ")) {
    try {
      const parsedPayload = JSON.parse(dataPayload);
      if (parsedPayload && typeof parsedPayload === "object" && (parsedPayload.object === "chat.completion.chunk" || parsedPayload.choices)) {
        let output = "";
        const reasoningPreview = Array.isArray(parsedPayload.choices)
          ? parsedPayload.choices
              .map((choice) => extractReasoningPreview(choice?.delta, { trimEdges: false }))
              .filter(Boolean)
              .join("")
          : "";
        output += appendVisibleThinkingChunk(reasoningPreview, state);

        const sanitizedPayload = sanitizeOpenAiStreamingPayload(parsedPayload);
        if (!sanitizedPayload) {
          return output;
        }

        if (payloadHasVisibleContent(sanitizedPayload)) {
          output += closeVisibleThinkingChunk(state);
        }

        output += `data: ${JSON.stringify(sanitizedPayload)}\n\n`;
        return output;
      }
    } catch {
      // Fall through to text cleanup below.
    }
  }

  const strippedEmbeddedPayload = stripEmbeddedStreamChunkPayload(strippedChunk);
  let normalizedChunk = strippedEmbeddedPayload !== null ? strippedEmbeddedPayload : strippedChunk;
  if (!normalizedChunk) {
    return "";
  }

  let content = normalizedChunk;
  if (normalizedChunk.startsWith("{")) {
    try {
      const parsedPayload = JSON.parse(normalizedChunk);
      if (parsedPayload && typeof parsedPayload === "object") {
        if (Array.isArray(parsedPayload.choices) && parsedPayload.choices.length > 0) {
          const visibleThinkingChunk = appendVisibleThinkingChunk(
            extractReasoningPreview(parsedPayload.choices[0]?.delta, { trimEdges: false }),
            state,
          );
          content =
            parsedPayload.choices[0]?.text ??
            parsedPayload.choices[0]?.delta?.content ??
            normalizedChunk;
          if (!content || content === normalizedChunk) {
            return visibleThinkingChunk;
          }
        } else if (typeof parsedPayload.text === "string") {
          content = parsedPayload.text;
        }
      }
    } catch {
      content = normalizedChunk;
    }
  }

  const sanitizedContent = stripThinkBlocks(content, { trimEdges: false });
  if (!sanitizedContent) {
    return "";
  }

  return `${closeVisibleThinkingChunk(state)}${buildStreamingChunk(sanitizedContent)}`;
}

function createOpencodeStreamResponse(upstreamResponse) {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let insideReasoningBlock = false;
  const streamState = {
    thinkingOpen: false,
    thinkingClosed: false,
    thinkingBuffer: [],
    thinkingBufferedChars: 0,
  };

  return new ReadableStream({
    async start(controller) {
      let doneSent = false;
      let buffered = "";

      try {
        for await (const chunk of upstreamResponse.body) {
          buffered += decoder.decode(chunk, { stream: true });
          const lines = buffered.split(/\r?\n/);
          buffered = lines.pop() ?? "";

          for (const line of lines) {
            const extracted = extractTaggedReasoningContent(line, insideReasoningBlock);
            insideReasoningBlock = extracted.insideReasoningBlock;

            const visibleThinkingChunk = appendVisibleThinkingChunk(extracted.reasoningChunk, streamState);
            if (visibleThinkingChunk) {
              controller.enqueue(encoder.encode(visibleThinkingChunk));
            }

            if (!extracted.contentChunk) {
              continue;
            }

            const standardizedChunk = standardizeOpencodeStreamingChunk(extracted.contentChunk, streamState);
            if (!standardizedChunk) {
              continue;
            }

            controller.enqueue(encoder.encode(standardizedChunk));
            if (standardizedChunk.includes("data: [DONE]")) {
              doneSent = true;
              controller.close();
              return;
            }
          }
        }

        buffered += decoder.decode();
        if (buffered) {
          const extracted = extractTaggedReasoningContent(buffered, insideReasoningBlock);
          const visibleThinkingChunk = appendVisibleThinkingChunk(extracted.reasoningChunk, streamState);
          if (visibleThinkingChunk) {
            controller.enqueue(encoder.encode(visibleThinkingChunk));
          }

          if (extracted.contentChunk) {
            const standardizedChunk = standardizeOpencodeStreamingChunk(extracted.contentChunk, streamState);
            if (standardizedChunk) {
              controller.enqueue(encoder.encode(standardizedChunk));
              if (standardizedChunk.includes("data: [DONE]")) {
                doneSent = true;
              }
            }
          }
        }

        const closingThinkChunk = closeVisibleThinkingChunk(streamState);
        if (closingThinkChunk) {
          controller.enqueue(encoder.encode(closingThinkChunk));
        }

        if (!doneSent) {
          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        }
        controller.close();
      } catch (error) {
        controller.error(error);
      } finally {
        upstreamResponse.body?.cancel?.();
      }
    },
  });
}

async function handleDirectOpencodeRequest(request, env, requestUrl) {
  if (!env.OPENCODE_API_KEY) {
    return applyCorsHeaders(request, buildMissingUpstreamKeyResponse(), env);
  }

  const providedToken = extractBearerToken(request);
  if (!providedToken || providedToken !== env.ADMIN_API_KEY) {
    return applyCorsHeaders(request, buildUnauthorizedResponse(), env);
  }

  const bodyAllowed = request.method !== "GET" && request.method !== "HEAD";
  const upstreamResponse = await fetch(buildOpencodeUpstreamUrl(requestUrl), {
    method: request.method,
    headers: buildUpstreamHeaders(request, env.OPENCODE_API_KEY),
    body: bodyAllowed ? await request.clone().arrayBuffer() : undefined,
  });

  const contentType = upstreamResponse.headers.get("content-type") ?? "";
  if (contentType.startsWith("text/event-stream")) {
    return applyCorsHeaders(
      request,
      new Response(createOpencodeStreamResponse(upstreamResponse), {
        status: upstreamResponse.status,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "X-Accel-Buffering": "no",
        },
      }),
      env,
    );
  }

  if (contentType.includes("application/json")) {
    const payload = sanitizeOpenAiCompletionPayload(await upstreamResponse.json());
    return applyCorsHeaders(
      request,
      new Response(JSON.stringify(payload), {
        status: upstreamResponse.status,
        headers: copyProxyResponseHeaders(upstreamResponse.headers),
      }),
      env,
    );
  }

  return applyCorsHeaders(
    request,
    new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: copyProxyResponseHeaders(upstreamResponse.headers),
    }),
    env,
  );
}

function buildCorsHeaders(request) {
  const origin = request.headers.get("Origin");
  const { pathname } = new URL(request.url);

  if (!origin || !isApiRequestPath(pathname)) {
    return null;
  }

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": CORS_ALLOWED_METHODS,
    "Access-Control-Allow-Headers":
      request.headers.get("Access-Control-Request-Headers") ?? CORS_DEFAULT_HEADERS,
    "Access-Control-Max-Age": "86400",
  };
}

function appendVaryHeader(headers, value) {
  const current = headers.get("Vary");
  if (!current) {
    headers.set("Vary", value);
    return;
  }

  const values = current
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (!values.includes(value)) {
    values.push(value);
    headers.set("Vary", values.join(", "));
  }
}

function applyCorsHeaders(request, response, env = {}) {
  const corsHeaders = buildCorsHeaders(request);
  if (!corsHeaders) {
    return response;
  }

  const responseWithCors = new Response(response.body, response);
  for (const [header, value] of Object.entries(corsHeaders)) {
    responseWithCors.headers.set(header, value);
  }
  appendVaryHeader(responseWithCors.headers, "Origin");
  return responseWithCors;
}

function buildPreflightResponse(request, env = {}) {
  const headers = buildCorsHeaders(request) ?? {};
  const response = new Response(null, { status: 204 });

  for (const [header, value] of Object.entries(headers)) {
    response.headers.set(header, value);
  }
  response.headers.set("Allow", CORS_ALLOWED_METHODS);
  appendVaryHeader(response.headers, "Origin");
  return response;
}

export class MultiLLMProxyContainer extends Container {
  defaultPort = 8080;
  requiredPorts = [8080];
  sleepAfter = "15m";

  constructor(ctx, env) {
    super(ctx, env);
    this.envVars = collectContainerEnv(env);
  }

  onStart() {
    console.log("Container starting", {
      envKeys: Object.keys(this.envVars).sort(),
      hasAdminApiKey: Boolean(this.envVars.ADMIN_API_KEY),
      hasFlaskSecretKey: Boolean(this.envVars.FLASK_SECRET_KEY),
      hasJwtSecret: Boolean(this.envVars.JWT_SECRET),
      hasOpenCodeApiKey: Boolean(this.envVars.OPENCODE_API_KEY),
    });
  }

  onError(error) {
    console.error("Container startup error", {
      message: error instanceof Error ? error.message : String(error),
      envKeys: Object.keys(this.envVars).sort(),
      hasAdminApiKey: Boolean(this.envVars.ADMIN_API_KEY),
      hasFlaskSecretKey: Boolean(this.envVars.FLASK_SECRET_KEY),
      hasJwtSecret: Boolean(this.envVars.JWT_SECRET),
      hasOpenCodeApiKey: Boolean(this.envVars.OPENCODE_API_KEY),
    });
  }
}

export default {
  async fetch(request, env) {
    const requestUrl = new URL(request.url);
    const apiPath = isApiRequestPath(requestUrl.pathname);
    const rootPath = requestUrl.pathname === "/";
    const healthPath = isDirectHealthPath(requestUrl.pathname);
    const opencodePath = isDirectOpencodePath(requestUrl.pathname);

    console.log("Worker env check", {
      hasAdminApiKey: Boolean(env.ADMIN_API_KEY),
      hasFlaskSecretKey: Boolean(env.FLASK_SECRET_KEY),
      hasJwtSecret: Boolean(env.JWT_SECRET),
      hasOpenCodeApiKey: Boolean(env.OPENCODE_API_KEY),
    });

    if (request.method === "OPTIONS" && apiPath) {
      return buildPreflightResponse(request, env);
    }

    if (healthPath) {
      return applyCorsHeaders(request, buildFallbackHealthResponse(), env);
    }

    if (opencodePath) {
      try {
        return await handleDirectOpencodeRequest(request, env, requestUrl);
      } catch (error) {
        console.error("Direct opencode fetch failed", error);
        return applyCorsHeaders(
          request,
          jsonResponse(
            {
              error: "Proxy unavailable",
              message: "The direct opencode worker fallback could not handle the request.",
            },
            { status: 502 },
          ),
          env,
        );
      }
    }

    try {
      const container = getContainer(env.MULTILLM_PROXY_CONTAINER, "primary");
      await container.startAndWaitForPorts({
        ports: [8080],
        cancellationOptions: {
          instanceGetTimeoutMS: 30000,
          portReadyTimeoutMS: 30000,
          waitInterval: 500,
        },
      });
      const bodyAllowed = request.method !== "GET" && request.method !== "HEAD";
      const headers = new Headers(request.headers);
      headers.delete("content-length");
      headers.delete("host");
      const forwardedRequest = new Request(requestUrl.toString(), {
        method: request.method,
        headers,
        body: bodyAllowed ? await request.clone().arrayBuffer() : undefined,
        redirect: "manual",
      });
      const response = await container.fetch(
        switchPort(forwardedRequest, 8080),
      );
      return applyCorsHeaders(request, response, env);
    } catch (error) {
      if (rootPath) {
        console.error("Container fetch failed", error);
        return buildRootFallbackResponse();
      }

      if (!apiPath) {
        console.error("Container fetch failed", error);
        return new Response("Proxy unavailable", {
          status: 502,
          headers: {
            "Content-Type": "text/plain; charset=UTF-8",
          },
        });
      }

      console.error("Container fetch failed", error);
      return applyCorsHeaders(
        request,
        new Response(
          JSON.stringify({
            error: "Proxy unavailable",
            message: "The proxy container could not handle the request.",
          }),
          {
            status: 502,
            headers: {
              "Content-Type": "application/json",
            },
          },
        ),
        env,
      );
    }
  },
};
