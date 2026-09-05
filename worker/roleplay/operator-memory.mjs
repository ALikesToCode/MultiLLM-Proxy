import { errorResponse, jsonResponse, readBoundedBytes } from "./transport.mjs";

function revision(state) {
  return `${state.turns || 0}:${state.updatedAt || 0}:${state.operatorRevision || 0}`;
}

function inspect(state, includeContext) {
  return { revision: revision(state), memory: state.memory, pins: state.operatorPins || [],
    profile: state.profile, branch: state.branch || null,
    retainedMessageCount: state.messages.length, protectedDirectiveCount: state.directives.length,
    completedTurns: state.turns, compactions: state.compactions,
    ...(includeContext ? { retainedMessages: state.messages, protectedDirectives: state.directives } : {}) };
}

function validPins(value) {
  return Array.isArray(value) && value.length <= 24 && value.every((text) =>
    typeof text === "string" && text.trim().length > 0 && text.length <= 500);
}

export async function handleOperatorMemory(session, request, operation) {
  if (request.method !== "POST") return errorResponse("Method not allowed", 405, "method_not_allowed");
  // Acquire synchronously through the same queue as turns. A pending stream must
  // never later overwrite an operator correction or be forked half-completed.
  if (session.pendingTurns) return errorResponse("Wait for the active turn before inspecting or changing memory", 409, "session_busy");
  let slot;
  try {
    slot = await session.turnQueue.acquire(request.signal, { maxPendingTurns: 1, queueTimeoutMs: 1000 });
    const { bytes } = await readBoundedBytes(request.body, operation === "import-branch" ? 1_048_576 : 32_768, request.signal);
    const body = JSON.parse(new TextDecoder().decode(bytes));
    const state = await session.stateRepository.load();
    if (operation === "import-branch") {
      if (state.turns || state.messages.length || state.directives.length || state.memory || state.branch || state.operatorPins?.length) {
        return errorResponse("Branch destination is not empty", 409, "branch_exists");
      }
      if (!body.state || !Array.isArray(body.state.messages) || !body.state.branch) return errorResponse("Invalid branch", 400, "invalid_branch");
      const next = { ...body.state, stats: {}, activeCredentials: {}, credentialUses: {}, recentRequests: [],
        compactionCheckpoint: null, operatorRevision: 0, updatedAt: Date.now() };
      await session.stateRepository.save(next);
      session.refreshSessionAlarm();
      return jsonResponse({ created: true, revision: revision(next) });
    }
    if (body.action === "inspect") return jsonResponse(inspect(state, body.include_context === true));
    if (body.revision !== revision(state)) return errorResponse("Memory changed; inspect it again before saving", 409, "revision_conflict");
    if (body.action === "export-branch") {
      if (body.confirm !== true) return errorResponse("Explicit branch confirmation is required", 400, "confirmation_required");
      const snapshot = JSON.stringify({ state });
      if (new TextEncoder().encode(snapshot).byteLength > 900_000) return errorResponse("Retained context exceeds the branch copy limit", 413, "branch_too_large");
      return jsonResponse({ state });
    }
    if (body.action !== "update" || !validPins(body.pins) || typeof body.summary !== "string" || body.summary.length > 4000) {
      return errorResponse("Use up to 24 pins of 500 characters and a summary of up to 4000 characters", 400, "invalid_memory");
    }
    const next = { ...state, memory: { ...state.memory, summary: body.summary }, operatorPins: body.pins.map((text) => text.trim()),
      operatorRevision: (state.operatorRevision || 0) + 1, compactionCheckpoint: null, updatedAt: Date.now() };
    await session.stateRepository.save(next);
    session.refreshSessionAlarm();
    return jsonResponse(inspect(next, false));
  } catch (error) {
    return errorResponse("Memory operation could not be completed", error.status || 400, error.code || "invalid_memory");
  } finally { slot?.finish(); }
}
