import {
  buildProviderHeaders,
  isSafeFallbackStatus,
} from "./config.mjs";
import {
  RoleplayRequestError,
  buildCompactionPayload,
  parseCompactionResponse,
} from "./memory.mjs";

const RESPONSE_HEADER_WHITELIST = new Set([
  "cache-control",
  "content-type",
  "date",
  "openai-processing-ms",
  "openai-version",
  "request-id",
  "retry-after",
  "vary",
  "x-request-id",
  "x-should-retry",
]);
const RESPONSE_HEADER_PREFIXES = [
  "anthropic-ratelimit-",
  "ratelimit-",
  "x-ratelimit-",
];

export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_COMPACTION_RESPONSE_BYTES = 512 * 1024;

export function jsonResponse(body, init = {}) {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(body), { ...init, headers });
}

export function errorResponse(
  message,
  status = 400,
  code = "invalid_request",
) {
  return jsonResponse(
    {
      error: {
        code,
        message,
        type: status >= 500 ? "server_error" : "invalid_request_error",
      },
    },
    { status },
  );
}

export function logRoleplayError(event, error, details = {}) {
  const candidateName = error instanceof Error ? error.name : "UnknownError";
  const errorName = /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(candidateName)
    ? candidateName
    : "Error";
  console.error(JSON.stringify({ event, errorName, ...details }));
}

export async function readBoundedBytes(stream, maximumBytes, signal) {
  if (!stream) {
    return { bytes: new Uint8Array(), firstByteMs: 0 };
  }

  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  let firstByteAt = 0;
  const startedAt = performance.now();

  try {
    while (true) {
      if (signal?.aborted) {
        throw new DOMException("Request aborted", "AbortError");
      }
      const { value, done } = await reader.read();
      if (done) {
        break;
      }
      if (!value) {
        continue;
      }
      if (!firstByteAt) {
        firstByteAt = performance.now();
      }
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      size += chunk.byteLength;
      if (size > maximumBytes) {
        await reader.cancel("Response exceeded configured limit");
        throw new RoleplayRequestError(
          "Upstream response exceeded the roleplay response limit",
          502,
        );
      }
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return {
    bytes,
    firstByteMs: firstByteAt ? firstByteAt - startedAt : 0,
  };
}

export function copyUpstreamResponseHeaders(headers) {
  const copied = new Headers();
  for (const [name, value] of headers.entries()) {
    const normalized = name.toLowerCase();
    if (
      RESPONSE_HEADER_WHITELIST.has(normalized) ||
      RESPONSE_HEADER_PREFIXES.some((prefix) => normalized.startsWith(prefix))
    ) {
      copied.set(name, value);
    }
  }
  return copied;
}

export function decorateRoleplayHeaders(
  headers,
  candidate,
  selectionReason,
  memoryStatus,
  estimatedInputTokens,
  maxOutputTokens,
  headerMs,
  fallbackCount,
) {
  headers.set("X-Roleplay-Provider", candidate.provider);
  headers.set("X-Roleplay-Model", candidate.model);
  headers.set("X-Roleplay-Selection", selectionReason);
  headers.set("X-Roleplay-Memory", memoryStatus);
  headers.set(
    "X-Roleplay-Estimated-Input-Tokens",
    String(estimatedInputTokens),
  );
  headers.set("X-Roleplay-Max-Output-Tokens", String(maxOutputTokens));
  headers.set("X-Roleplay-Fallback-Count", String(fallbackCount));
  headers.set(
    "Server-Timing",
    `roleplay_upstream_headers;dur=${Math.max(0, headerMs).toFixed(1)}`,
  );
  return headers;
}

function updateEwma(current, value, alpha = 0.25) {
  if (!Number.isFinite(current)) {
    return value;
  }
  return current * (1 - alpha) + value * alpha;
}

export function recordModelResult(
  state,
  candidate,
  { success, ttfbMs, totalMs, status, now = Date.now() },
) {
  const previous = state.stats[candidate.key] ?? {
    provider: candidate.provider,
    model: candidate.model,
    family: candidate.family,
    attempts: 0,
    successes: 0,
    failures: 0,
    consecutiveFailures: 0,
  };
  const attempts = previous.attempts + 1;
  const successes = previous.successes + (success ? 1 : 0);
  const failures = previous.failures + (success ? 0 : 1);
  const consecutiveFailures = success
    ? 0
    : (previous.consecutiveFailures ?? 0) + 1;
  let cooldownUntil = 0;
  if (!success) {
    if (status === 429) {
      cooldownUntil = now + 60_000;
    } else if ([401, 403, 404].includes(status)) {
      cooldownUntil = now + 300_000;
    } else if (consecutiveFailures >= 2) {
      cooldownUntil = now + 120_000;
    }
  }

  return {
    ...state,
    stats: {
      ...state.stats,
      [candidate.key]: {
        ...previous,
        attempts,
        successes,
        failures,
        consecutiveFailures,
        cooldownUntil,
        ewmaTtfbMs: success
          ? updateEwma(previous.ewmaTtfbMs, ttfbMs)
          : previous.ewmaTtfbMs,
        ewmaTotalMs: success
          ? updateEwma(previous.ewmaTotalMs, totalMs)
          : previous.ewmaTotalMs,
        lastStatus: status,
        lastUsedAt: now,
      },
    },
  };
}

async function fetchCandidate(candidate, payload, env, settings, signal, key) {
  const controller = new AbortController();
  const abort = () => controller.abort(signal?.reason);
  if (signal?.aborted) {
    abort();
  } else {
    signal?.addEventListener("abort", abort, { once: true });
  }
  const timeout = setTimeout(
    () => controller.abort("Upstream header timeout"),
    settings.upstreamHeaderTimeoutMs,
  );
  const startedAt = performance.now();

  try {
    const response = await fetch(candidate.endpoint, {
      method: "POST",
      headers: buildProviderHeaders(candidate, env, key),
      body: JSON.stringify(payload),
      redirect: "manual",
      signal: controller.signal,
    });
    return {
      response,
      controller,
      startedAt,
      headerMs: performance.now() - startedAt,
      cleanup() {
        clearTimeout(timeout);
        signal?.removeEventListener("abort", abort);
      },
    };
  } catch (error) {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", abort);
    throw error;
  }
}

export async function requestCompaction(
  state,
  plan,
  candidates,
  env,
  settings,
  signal,
) {
  let fallbackCount = 0;
  for (const candidate of candidates) {
    const payload = buildCompactionPayload(state, plan, candidate, settings);
    let attempted;
    try {
      attempted = await fetchCandidate(
        candidate,
        payload,
        env,
        settings,
        signal,
        "",
      );
    } catch (error) {
      logRoleplayError("roleplay_compaction_fetch_failed", error, {
        provider: candidate.provider,
        model: candidate.model,
      });
      throw error;
    }

    const { response } = attempted;
    attempted.cleanup();
    if (!response.ok) {
      if (isSafeFallbackStatus(response.status)) {
        fallbackCount += 1;
        await response.body?.cancel();
        continue;
      }
      await response.body?.cancel();
      throw new Error("Compaction provider returned an ambiguous failure");
    }

    const { bytes } = await readBoundedBytes(
      response.body,
      MAX_COMPACTION_RESPONSE_BYTES,
      signal,
    );
    const payloadJson = JSON.parse(new TextDecoder().decode(bytes));
    return {
      candidate,
      digest: parseCompactionResponse(payloadJson),
      fallbackCount,
    };
  }
  throw new Error("No configured model accepted memory compaction");
}

export async function attemptRoleplayCandidates(
  state,
  candidates,
  payloadFactory,
  env,
  settings,
  signal,
  idempotencyKey,
) {
  let nextState = state;
  let fallbackCount = 0;

  for (const candidate of candidates) {
    let attempted;
    try {
      attempted = await fetchCandidate(
        candidate,
        payloadFactory(candidate),
        env,
        settings,
        signal,
        idempotencyKey,
      );
    } catch (error) {
      nextState = recordModelResult(nextState, candidate, {
        success: false,
        ttfbMs: 0,
        totalMs: 0,
        status: 0,
      });
      logRoleplayError("roleplay_provider_fetch_failed", error, {
        provider: candidate.provider,
        model: candidate.model,
      });
      return {
        state: nextState,
        terminalResponse: errorResponse(
          "Selected provider outcome is ambiguous; automatic fallback was stopped",
          502,
          "ambiguous_provider_failure",
        ),
      };
    }

    if (attempted.response.ok) {
      return {
        ...attempted,
        candidate,
        state: nextState,
        fallbackCount,
      };
    }

    nextState = recordModelResult(nextState, candidate, {
      success: false,
      ttfbMs: attempted.headerMs,
      totalMs: attempted.headerMs,
      status: attempted.response.status,
    });
    attempted.cleanup();

    if (isSafeFallbackStatus(attempted.response.status)) {
      fallbackCount += 1;
      await attempted.response.body?.cancel();
      continue;
    }

    return {
      state: nextState,
      terminalResponse: new Response(attempted.response.body, {
        status: attempted.response.status,
        statusText: attempted.response.statusText,
        headers: copyUpstreamResponseHeaders(attempted.response.headers),
      }),
    };
  }

  return {
    state: nextState,
    terminalResponse: errorResponse(
      "No configured provider accepted the requested roleplay model",
      503,
      "no_roleplay_provider",
    ),
  };
}

function sseAssistantCollector(maximumCharacters = 64_000) {
  let buffered = "";
  let assistant = "";

  const consumeLine = (line) => {
    if (!line.startsWith("data:")) {
      return;
    }
    const data = line.slice(5).trim();
    if (!data || data === "[DONE]") {
      return;
    }
    try {
      const payload = JSON.parse(data);
      const content = payload?.choices?.[0]?.delta?.content;
      if (typeof content === "string" && assistant.length < maximumCharacters) {
        assistant += content.slice(0, maximumCharacters - assistant.length);
      }
    } catch {
      // Preserve provider stream even when a non-JSON data event appears.
    }
  };

  return {
    consume(text) {
      buffered += text;
      const lines = buffered.split(/\r?\n/);
      buffered = lines.pop() ?? "";
      for (const line of lines) {
        consumeLine(line);
      }
    },
    finish(text = "") {
      buffered += text;
      if (buffered) {
        consumeLine(buffered);
      }
      return assistant;
    },
  };
}

export function createObservedStream(
  upstreamBody,
  requestSignal,
  upstreamController,
  onComplete,
) {
  let resolveCompletion;
  const completion = new Promise((resolve) => {
    resolveCompletion = resolve;
  });
  const reader = upstreamBody.getReader();
  const decoder = new TextDecoder();
  const collector = sseAssistantCollector();
  let settled = false;
  let released = false;
  let firstByteAt = 0;
  const streamStartedAt = performance.now();

  const releaseReader = () => {
    if (!released) {
      released = true;
      reader.releaseLock();
    }
  };

  const settle = async (result) => {
    if (settled) {
      return;
    }
    settled = true;
    try {
      await onComplete(result);
    } catch (error) {
      logRoleplayError("roleplay_stream_state_write_failed", error);
    } finally {
      resolveCompletion();
    }
  };

  const stream = new ReadableStream({
    async pull(controller) {
      try {
        if (requestSignal.aborted) {
          throw new DOMException("Request aborted", "AbortError");
        }
        const { value, done } = await reader.read();
        if (done) {
          const assistant = collector.finish(decoder.decode());
          releaseReader();
          controller.close();
          void settle({
            success: true,
            assistant,
            ttfbMs: firstByteAt ? firstByteAt - streamStartedAt : 0,
            streamMs: performance.now() - streamStartedAt,
          });
          return;
        }
        if (!value) {
          return;
        }
        if (!firstByteAt) {
          firstByteAt = performance.now();
        }
        collector.consume(decoder.decode(value, { stream: true }));
        controller.enqueue(value);
      } catch (error) {
        upstreamController.abort(error);
        releaseReader();
        void settle({
          success: false,
          assistant: "",
          ttfbMs: firstByteAt ? firstByteAt - streamStartedAt : 0,
          streamMs: performance.now() - streamStartedAt,
        });
        controller.error(error);
      }
    },
    async cancel(reason) {
      upstreamController.abort(reason);
      try {
        await reader.cancel(reason);
      } finally {
        releaseReader();
        await settle({
          success: false,
          assistant: "",
          ttfbMs: firstByteAt ? firstByteAt - streamStartedAt : 0,
          streamMs: performance.now() - streamStartedAt,
        });
      }
    },
  });

  return { stream, completion };
}
