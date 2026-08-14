import {
  buildProviderHeaders,
  isSafeFallbackStatus,
} from "./config.mjs";
import { prepareRoleplayCandidates } from "./capacity.mjs";
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
  queueMs = 0,
  compactionMs = 0,
  totalToHeadersMs = headerMs,
  optimization = {},
) {
  const inputBefore = Math.max(
    estimatedInputTokens,
    Number(optimization.estimatedInputBefore) || estimatedInputTokens,
  );
  const inputSaved = Math.max(
    0,
    Number(optimization.inputTokensSaved) || 0,
  );
  const messagesOptimized = Math.max(
    0,
    Number(optimization.messagesOptimized) || 0,
  );
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
    "X-MultiLLM-Optimization",
    inputSaved > 0 || messagesOptimized > 0 ? "applied" : "skipped",
  );
  headers.set("X-MultiLLM-Optimization-Mode", "summarize");
  headers.set("X-MultiLLM-Estimated-Input-Before", String(inputBefore));
  headers.set(
    "X-MultiLLM-Estimated-Input-After",
    String(estimatedInputTokens),
  );
  headers.set(
    "X-MultiLLM-Messages-Summarized",
    String(messagesOptimized),
  );
  if (optimization.promptCache) {
    headers.set(
      "X-MultiLLM-Prompt-Cache",
      optimization.promptCache.status,
    );
    headers.set(
      "X-MultiLLM-Prompt-Cache-Mode",
      optimization.promptCache.mode,
    );
    headers.set(
      "X-MultiLLM-Prompt-Cache-Estimated-Tokens",
      String(optimization.promptCache.estimatedInputTokens),
    );
  }
  headers.set(
    "Server-Timing",
    [
      `roleplay_queue;dur=${Math.max(0, queueMs).toFixed(1)}`,
      `roleplay_compaction;dur=${Math.max(0, compactionMs).toFixed(1)}`,
      `roleplay_upstream_headers;dur=${Math.max(0, headerMs).toFixed(1)}`,
      `roleplay_total_to_headers;dur=${Math.max(0, totalToHeadersMs).toFixed(1)}`,
    ].join(", "),
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
    } else if ([401, 402, 403, 404].includes(status)) {
      cooldownUntil = now + 300_000;
    } else if (consecutiveFailures >= 2) {
      cooldownUntil = now + 120_000;
    }
  }

  const activeCredentials = { ...(state.activeCredentials ?? {}) };
  const credentialUses = {
    ...(state.credentialUses ?? {}),
    [candidate.provider]: {
      ...(state.credentialUses?.[candidate.provider] ?? {}),
    },
  };
  if (success) {
    activeCredentials[candidate.provider] = candidate.credentialId;
    credentialUses[candidate.provider][candidate.credentialId] =
      (credentialUses[candidate.provider][candidate.credentialId] ?? 0) + 1;
  } else if (
    activeCredentials[candidate.provider] === candidate.credentialId
  ) {
    delete activeCredentials[candidate.provider];
    credentialUses[candidate.provider][candidate.credentialId] = 0;
  }

  return {
    ...state,
    activeCredentials,
    credentialUses,
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
  let cleaned = false;
  if (signal?.aborted) {
    abort();
  } else {
    signal?.addEventListener("abort", abort, { once: true });
  }
  const timeout = setTimeout(
    () => controller.abort("upstream_header_timeout"),
    settings.upstreamHeaderTimeoutMs,
  );
  const startedAt = performance.now();

  try {
    const headers = buildProviderHeaders(candidate, env, key);
    const containerNamespace = env.MULTILLM_PROXY_CONTAINER;
    const useOpenCodeContainer =
      candidate.provider === "opencode" &&
      env.ADMIN_API_KEY &&
      containerNamespace &&
      typeof containerNamespace.getByName === "function";
    if (useOpenCodeContainer) {
      headers.set("X-MultiLLM-Api-Key", env.ADMIN_API_KEY);
    }
    const requestInit = {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      redirect: "manual",
      signal: controller.signal,
    };
    const response = useOpenCodeContainer
      ? await containerNamespace.getByName("primary").fetch(
          new Request(
            "https://roleplay.internal/opencode/v1/chat/completions",
            requestInit,
          ),
        )
      : await fetch(candidate.endpoint, requestInit);
    clearTimeout(timeout);
    return {
      response,
      controller,
      startedAt,
      headerMs: performance.now() - startedAt,
      cleanup() {
        if (cleaned) {
          return;
        }
        cleaned = true;
        clearTimeout(timeout);
        signal?.removeEventListener("abort", abort);
      },
    };
  } catch (error) {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", abort);
    if (
      ["upstream_header_timeout", "compaction_timeout"].includes(
        controller.signal.reason,
      )
    ) {
      const timeoutError = new Error(
        controller.signal.reason === "compaction_timeout"
          ? "Memory compaction exceeded its total time budget"
          : "Upstream response headers exceeded the time budget",
      );
      timeoutError.name = "TimeoutError";
      throw timeoutError;
    }
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
  const compactionController = new AbortController();
  const forwardAbort = () =>
    compactionController.abort(signal?.reason);
  if (signal?.aborted) {
    forwardAbort();
  } else {
    signal?.addEventListener("abort", forwardAbort, { once: true });
  }
  const startedAt = performance.now();
  const deadlineAt = startedAt + settings.compactionTimeoutMs;
  const deadline = setTimeout(
    () => compactionController.abort("compaction_timeout"),
    settings.compactionTimeoutMs,
  );
  let fallbackCount = 0;
  try {
    const compactionCandidates = prepareRoleplayCandidates(
      candidates,
      plan.compactableTokens + settings.memoryTargetTokens + 1_024,
      settings.compactionMaxTokens,
      settings,
    );
    for (const candidate of compactionCandidates) {
      if (compactionController.signal.aborted) {
        const error = new Error(
          "Memory compaction exceeded its total time budget",
        );
        error.name = "TimeoutError";
        throw error;
      }
      const payload = buildCompactionPayload(
        state,
        plan,
        candidate,
        settings,
      );
      let attempted;
      try {
        attempted = await fetchCandidate(
          candidate,
          payload,
          env,
          {
            ...settings,
            upstreamHeaderTimeoutMs: Math.max(
              1,
              deadlineAt - performance.now(),
            ),
          },
          compactionController.signal,
          "",
        );
      } catch (error) {
        logRoleplayError("roleplay_compaction_fetch_failed", error, {
          provider: candidate.provider,
          model: candidate.model,
          elapsedMs: Math.round(performance.now() - startedAt),
          budgetMs: settings.compactionTimeoutMs,
        });
        throw error;
      }

      const { response } = attempted;
      if (!response.ok) {
        attempted.cleanup();
        logRoleplayError(
          "roleplay_compaction_provider_rejected",
          new Error("Compaction provider rejected the request"),
          {
            provider: candidate.provider,
            model: candidate.model,
            status: response.status,
            safeFallback: isSafeFallbackStatus(response.status),
          },
        );
        if (isSafeFallbackStatus(response.status)) {
          fallbackCount += 1;
          await response.body?.cancel();
          continue;
        }
        await response.body?.cancel();
        throw new Error(
          "Compaction provider returned an ambiguous failure",
        );
      }

      try {
        const { bytes } = await readBoundedBytes(
          response.body,
          MAX_COMPACTION_RESPONSE_BYTES,
          attempted.controller.signal,
        );
        const payloadJson = JSON.parse(
          new TextDecoder().decode(bytes),
        );
        return {
          candidate,
          digest: parseCompactionResponse(payloadJson),
          fallbackCount,
        };
      } catch (error) {
        logRoleplayError("roleplay_compaction_parse_failed", error, {
          provider: candidate.provider,
          model: candidate.model,
          status: response.status,
        });
        throw error;
      } finally {
        attempted.cleanup();
      }
    }
    throw new Error("No configured model accepted memory compaction");
  } finally {
    clearTimeout(deadline);
    signal?.removeEventListener("abort", forwardAbort);
  }
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
    let preparedPayload;
    try {
      preparedPayload = await payloadFactory(candidate);
      attempted = await fetchCandidate(
        candidate,
        preparedPayload?.payload ?? preparedPayload,
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
        promptCache: preparedPayload?.promptCache,
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
