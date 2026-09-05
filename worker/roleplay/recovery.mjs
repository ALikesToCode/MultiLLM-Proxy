import { errorResponse, jsonResponse, readBoundedBytes } from "./transport.mjs";
import { createVisibleRoleplayContentCollector } from "./reasoning-output.mjs";

const KEY = "operator_recovery_v1";
const MAX_BYTES = 100_000;

export function recoveryTemplate(payload, messages) {
  if (payload.recovery_enabled !== true) return null;
  const result = { model: payload.model || "roleplay:auto", messages,
    routing: payload.routing, reasoning_effort: payload.reasoning_effort,
    max_tokens: payload.max_tokens || 2048, stream: true,
    memory: { mode: "off" }, history_mode: "replace", recovery_enabled: true };
  for (const name of ["temperature", "top_p", "top_k", "seed", "frequency_penalty", "presence_penalty", "output_mode"]) {
    if (payload[name] !== undefined) result[name] = payload[name];
  }
  return new TextEncoder().encode(JSON.stringify(result)).byteLength <= 60_000 ? result : null;
}

export async function preserveRecovery(storage, template, result, traceId) {
  if (!template || result.success) return;
  const visible = createVisibleRoleplayContentCollector();
  const partial = typeof result.visiblePartial === "string" ? result.visiblePartial
    : visible.consume(result.assistant || "") + visible.finish();
  const snapshot = { token: crypto.randomUUID(), traceId, expiresAt: Date.now() + 86_400_000,
    partial: partial.slice(0, 16_000),
    truncated: result.partialTruncated === true || partial.length > 16_000,
    payload: template, reason: result.reason || "interrupted" };
  if (new TextEncoder().encode(JSON.stringify(snapshot)).byteLength > MAX_BYTES) return;
  await storage.put(KEY, snapshot);
}

export async function handleRecoverySnapshot(session, request) {
  if (session.pendingTurns) return errorResponse("Wait for the active turn to settle", 409, "session_busy");
  let slot;
  try {
    slot = await session.turnQueue.acquire(request.signal, { maxPendingTurns: 1 });
    const { bytes } = await readBoundedBytes(request.body, 2048, request.signal);
    const body = JSON.parse(new TextDecoder().decode(bytes));
    const snapshot = await session.ctx.storage.get(KEY);
    if (!snapshot || snapshot.expiresAt <= Date.now()) {
      if (snapshot) await session.ctx.storage.delete(KEY);
      return errorResponse("No unexpired opt-in recovery snapshot is available", 404, "recovery_unavailable");
    }
    if (body.action === "inspect") {
      return jsonResponse({ token: snapshot.token, partial: snapshot.partial, expiresAt: snapshot.expiresAt,
        traceId: snapshot.traceId, reason: snapshot.reason, truncated: snapshot.truncated, resumableTransport: false });
    }
    if (body.confirm !== true || body.token !== snapshot.token || !["continue", "regenerate"].includes(body.action)) {
      return errorResponse("Confirm the new generation using the latest recovery token", 409, "recovery_conflict");
    }
    if (body.action === "continue" && !snapshot.partial.trim()) return errorResponse("No visible partial output exists; regenerate instead", 400, "empty_partial");
    if (body.action === "continue" && snapshot.truncated) return errorResponse("The retained partial is truncated; regenerate instead", 400, "truncated_partial");
    // Consume before dispatch. A network error must not silently replay billing.
    await session.ctx.storage.delete(KEY);
    const payload = structuredClone(snapshot.payload);
    payload.routing = { ...payload.routing, fallback: "none" };
    if (body.action === "continue") payload.messages.push(
      { role: "assistant", content: snapshot.partial },
      { role: "user", content: "Continue from the end of the partial reply without repeating it. Complete the current scene beat." });
    return jsonResponse({ payload });
  } catch (error) {
    return errorResponse("Recovery operation failed", error.status || 400, "recovery_failed");
  } finally { slot?.finish(); }
}
