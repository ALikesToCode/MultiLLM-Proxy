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
import { fragmentChatPayload } from "./message-fragments.mjs";
import { classifyExplicitProviderError } from "./provider-errors.mjs";
import { recordThroughputObservation } from "./model-performance.mjs";
import {
  injectRoleplayRefusalControl,
  roleplayRefusalFallbackCandidates,
} from "./refusal-fallback.mjs";

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
const MAX_LATENCY_SAMPLES = 64;

class RoleplayPreResponseFailure extends Error {
  constructor(kind, cause) {
    super("Roleplay provider failed before response headers");
    this.name = "RoleplayPreResponseFailure";
    this.kind = kind;
    this.cause = cause;
  }
}

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

function safeErrorName(error) {
  const candidateName = error instanceof Error ? error.name : "UnknownError";
  return /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(candidateName)
    ? candidateName
    : "Error";
}

export function logRoleplayError(event, error, details = {}) {
  const errorName = safeErrorName(error);
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
  const abort = () => { void reader.cancel().catch(() => {}); };
  signal?.addEventListener("abort", abort, { once: true });

  try {
    while (true) {
      if (signal?.aborted) {
        throw new DOMException("Request aborted", "AbortError");
      }
      const { value, done } = await reader.read();
      if (signal?.aborted) {
        throw new DOMException("Request aborted", "AbortError");
      }
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
    signal?.removeEventListener("abort", abort);
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

function terminalProviderResponse(attempted, candidate, fallbackCount) {
  const headers = copyUpstreamResponseHeaders(attempted.response.headers);
  headers.set("X-Roleplay-Provider", candidate.provider);
  headers.set("X-Roleplay-Model", candidate.model);
  headers.set("X-Roleplay-Fallback-Count", String(fallbackCount));
  headers.set("X-Roleplay-Failure-Kind", "http_status");
  return new Response(attempted.response.body, {
    status: attempted.response.status,
    statusText: attempted.response.statusText,
    headers,
  });
}

async function handleCandidateHttpFailure(
  state,
  candidate,
  attempted,
  settings,
  fallbackCount,
) {
  const nextState = recordModelResult(state, candidate, {
    success: false,
    ttfbMs: attempted.headerMs,
    totalMs: attempted.headerMs,
    status: attempted.response.status,
  });
  const explicitProviderError = settings.providerErrorFallbackEnabled
    ? await classifyExplicitProviderError(attempted.response)
    : null;
  attempted.cleanup();

  const safeFallback =
    isSafeFallbackStatus(attempted.response.status) ||
    Boolean(explicitProviderError);
  logRoleplayError(
    "roleplay_provider_rejected",
    new Error("Roleplay provider rejected the request"),
    {
      provider: candidate.provider,
      model: candidate.model,
      status: attempted.response.status,
      providerErrorCode: explicitProviderError?.code,
      safeFallback,
    },
  );

  if (safeFallback) {
    await attempted.response.body?.cancel();
    return {
      state: nextState,
      fallbackCount: fallbackCount + 1,
      shouldAdvance: true,
    };
  }
  return {
    state: nextState,
    terminalResponse: terminalProviderResponse(
      attempted,
      candidate,
      fallbackCount,
    ),
  };
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
  timings = {},
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
      `roleplay_state_load;dur=${Math.max(0, timings.stateLoadMs ?? 0).toFixed(1)}`,
      `roleplay_credentials;dur=${Math.max(0, timings.credentialCheckMs ?? 0).toFixed(1)}`,
      `roleplay_compaction;dur=${Math.max(0, compactionMs).toFixed(1)}`,
      `roleplay_prepare;dur=${Math.max(0, timings.preparationMs ?? 0).toFixed(1)}`,
      `roleplay_upstream_headers;dur=${Math.max(0, headerMs).toFixed(1)}`,
      `roleplay_total_to_headers;dur=${Math.max(0, totalToHeadersMs).toFixed(1)}`,
    ].join(", "),
  );
  headers.set(
    "X-Roleplay-State-Cache",
    timings.stateCacheHit ? "hit" : "miss",
  );
  headers.set(
    "X-Roleplay-Credential-Check",
    timings.credentialCheckPerformed ? "performed" : "skipped",
  );
  return headers;
}

export function createRoleplayTimingSummary({
  queueMs,
  stateLoadMs,
  credentialCheckMs,
  compactionMs,
  headerMs,
  turnStartedAt,
  stateCacheHit,
  credentialCheckPerformed,
}) {
  const totalToHeadersMs = queueMs + performance.now() - turnStartedAt;
  return {
    queueMs,
    stateLoadMs,
    credentialCheckMs,
    preparationMs: Math.max(
      0,
      totalToHeadersMs -
        queueMs -
        stateLoadMs -
        credentialCheckMs -
        compactionMs -
        headerMs,
    ),
    totalToHeadersMs,
    stateCacheHit,
    credentialCheckPerformed,
  };
}

function updateEwma(current, value, alpha = 0.25) {
  if (!Number.isFinite(current)) {
    return value;
  }
  return current * (1 - alpha) + value * alpha;
}

function appendLatencySample(values, value) {
  if (!Number.isFinite(value) || value < 0) {
    return Array.isArray(values) ? values : [];
  }
  return [...(Array.isArray(values) ? values : []), value].slice(
    -MAX_LATENCY_SAMPLES,
  );
}

function percentile(values, percentileValue) {
  if (!Array.isArray(values) || !values.length) {
    return null;
  }
  const ordered = [...values].sort((left, right) => left - right);
  const index = Math.max(
    0,
    Math.ceil((percentileValue / 100) * ordered.length) - 1,
  );
  return Math.round(ordered[index]);
}

export function modelLatencyPercentiles(stats) {
  const ttfb = stats?.ttfbSamplesMs ?? [];
  const total = stats?.totalSamplesMs ?? [];
  return {
    sample_count: Math.min(ttfb.length, total.length),
    ttfb_ms: {
      p50: percentile(ttfb, 50),
      p95: percentile(ttfb, 95),
      p99: percentile(ttfb, 99),
    },
    total_ms: {
      p50: percentile(total, 50),
      p95: percentile(total, 95),
      p99: percentile(total, 99),
    },
  };
}

export function recordModelResult(
  state,
  candidate,
  { success, ttfbMs, totalMs, status, performance, now = Date.now() },
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
  const sampleLatency = success && (performance?.upstreamCallCount ?? 1) === 1;
  const successes = previous.successes + (success ? 1 : 0);
  const failures = previous.failures + (success ? 0 : 1);
  const consecutiveFailures = success
    ? 0
    : (previous.consecutiveFailures ?? 0) + 1;
  let cooldownUntil = 0;
  if (!success) {
    if (status === 429) {
      cooldownUntil = now + 60_000;
    } else if ([400, 401, 402, 403, 404, 415, 422].includes(status)) {
      cooldownUntil = now + 300_000;
    } else if (status === 503) {
      cooldownUntil = now + 120_000;
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
        ...(success
          ? recordThroughputObservation(previous, performance)
          : {}),
        attempts,
        successes,
        failures,
        consecutiveFailures,
        cooldownUntil,
        ewmaTtfbMs: sampleLatency
          ? updateEwma(previous.ewmaTtfbMs, ttfbMs)
          : previous.ewmaTtfbMs,
        ewmaTotalMs: sampleLatency
          ? updateEwma(previous.ewmaTotalMs, totalMs)
          : previous.ewmaTotalMs,
        ttfbSamplesMs: sampleLatency
          ? appendLatencySample(previous.ttfbSamplesMs, ttfbMs)
          : previous.ttfbSamplesMs,
        totalSamplesMs: sampleLatency
          ? appendLatencySample(previous.totalSamplesMs, totalMs)
          : previous.totalSamplesMs,
        lastStatus: status,
        lastUsedAt: now,
      },
    },
  };
}

export function recordModelRefusal(
  state,
  candidate,
  now = Date.now(),
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
  return {
    ...state,
    stats: {
      ...state.stats,
      [candidate.key]: {
        ...previous,
        semanticRefusals: (previous.semanticRefusals ?? 0) + 1,
        lastSemanticRefusalAt: now,
        lastUsedAt: now,
      },
    },
  };
}

export function recordRoleplayCompletionResult(
  state,
  candidate,
  result,
) {
  const { reason, ...modelResult } = result;
  return reason === "refusal_fallback_failed"
    ? state
    : recordModelResult(state, candidate, modelResult);
}

export function applyRoleplayRouteHeaders(
  headers,
  candidate,
  fallbackCount,
) {
  headers.set("X-Roleplay-Provider", candidate.provider);
  headers.set("X-Roleplay-Model", candidate.model);
  headers.set("X-Roleplay-Fallback-Count", String(fallbackCount));
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
      body: JSON.stringify(fragmentChatPayload(payload)),
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
    const failureKind = signal?.aborted
      ? "client_abort"
      : controller.signal.reason === "compaction_timeout"
        ? "compaction_timeout"
        : controller.signal.reason === "upstream_header_timeout"
          ? "upstream_header_timeout"
          : "transport_rejection";
    throw new RoleplayPreResponseFailure(failureKind, error);
  }
}

function terminalPreResponseFailure(
  candidate,
  failure,
  fallbackCount,
  fallbackEnabled,
) {
  if (!fallbackEnabled) {
    return errorResponse(
      "Selected provider outcome is ambiguous; automatic fallback was stopped",
      502,
      "ambiguous_provider_failure",
    );
  }

  const timedOut = failure.kind === "upstream_header_timeout";
  const response = errorResponse(
    timedOut
      ? `${candidate.provider} did not return response headers before the timeout and no fallback candidate remained`
      : `${candidate.provider} transport failed before response headers and no fallback candidate remained`,
    timedOut ? 504 : 502,
    timedOut ? "provider_header_timeout" : "provider_transport_failure",
  );
  response.headers.set("X-Roleplay-Provider", candidate.provider);
  response.headers.set("X-Roleplay-Model", candidate.model);
  response.headers.set("X-Roleplay-Fallback-Count", String(fallbackCount));
  response.headers.set("X-Roleplay-Failure-Kind", failure.kind);
  return response;
}

function handleCandidatePreResponseFailure(
  state,
  candidate,
  error,
  settings,
  hasFallbackCandidate,
  fallbackCount,
) {
  const failure =
    error instanceof RoleplayPreResponseFailure ? error : null;
  const clientAborted = failure?.kind === "client_abort";
  const nextState = clientAborted
    ? state
    : recordModelResult(state, candidate, {
        success: false,
        ttfbMs: 0,
        totalMs: 0,
        status: failure?.kind === "upstream_header_timeout" ? 504 : 0,
      });
  const shouldAdvance = Boolean(
    failure &&
      !clientAborted &&
      settings.preResponseFallbackEnabled &&
      hasFallbackCandidate,
  );
  logRoleplayError("roleplay_provider_fetch_failed", error, {
    provider: candidate.provider,
    model: candidate.model,
    failureKind: failure?.kind ?? "unknown",
    causeName: failure ? safeErrorName(failure.cause) : undefined,
    fallback: shouldAdvance,
  });

  if (clientAborted) {
    return {
      state: nextState,
      terminalResponse: errorResponse(
        "Roleplay request was aborted by the client",
        499,
        "request_aborted",
      ),
    };
  }
  if (shouldAdvance) {
    return {
      state: nextState,
      fallbackCount: fallbackCount + 1,
      shouldAdvance: true,
    };
  }
  return {
    state: nextState,
    terminalResponse: failure
      ? terminalPreResponseFailure(
          candidate,
          failure,
          fallbackCount,
          settings.preResponseFallbackEnabled,
        )
      : errorResponse(
          "Selected provider outcome is ambiguous; automatic fallback was stopped",
          502,
          "ambiguous_provider_failure",
        ),
  };
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

  for (
    let candidateIndex = 0;
    candidateIndex < candidates.length;
    candidateIndex += 1
  ) {
    const candidate = candidates[candidateIndex];
    const refusalFallbackCandidates = settings.refusalFallbackEnabled
      ? roleplayRefusalFallbackCandidates(candidates, candidateIndex)
      : [];
    let attempted;
    let preparedPayload;
    try {
      preparedPayload = await payloadFactory(candidate);
    } catch (error) {
      logRoleplayError("roleplay_provider_payload_failed", error, {
        provider: candidate.provider,
        model: candidate.model,
      });
      return {
        state: nextState,
        terminalResponse: errorResponse(
          "Unable to prepare the selected provider request",
          500,
          "provider_request_preparation_failed",
        ),
      };
    }

    const upstreamPayload = refusalFallbackCandidates.length
      ? injectRoleplayRefusalControl(
          preparedPayload?.payload ?? preparedPayload,
        )
      : preparedPayload?.payload ?? preparedPayload;

    try {
      attempted = await fetchCandidate(
        candidate,
        upstreamPayload,
        env,
        settings,
        signal,
        idempotencyKey,
      );
    } catch (error) {
      const failure = handleCandidatePreResponseFailure(
        nextState,
        candidate,
        error,
        settings,
        candidateIndex + 1 < candidates.length,
        fallbackCount,
      );
      nextState = failure.state;
      if (failure.shouldAdvance) {
        fallbackCount = failure.fallbackCount;
        continue;
      }
      return {
        state: nextState,
        terminalResponse: failure.terminalResponse,
      };
    }

    if (attempted.response.ok) {
      return {
        ...attempted,
        candidate,
        state: nextState,
        fallbackCount,
        promptCache: preparedPayload?.promptCache,
        refusalFallbackCandidates,
      };
    }

    const failure = await handleCandidateHttpFailure(
      nextState,
      candidate,
      attempted,
      settings,
      fallbackCount,
    );
    nextState = failure.state;
    if (failure.shouldAdvance) {
      fallbackCount = failure.fallbackCount;
      continue;
    }
    return {
      state: nextState,
      terminalResponse: failure.terminalResponse,
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
