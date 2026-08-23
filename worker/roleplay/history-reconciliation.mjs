function messageSignature(message) {
  return JSON.stringify([
    message?.role ?? "",
    message?.name ?? "",
    message?.tool_call_id ?? "",
    message?.content ?? "",
  ]);
}

function isPrefix(prefix, messages) {
  if (prefix.length > messages.length) {
    return false;
  }
  for (let index = 0; index < prefix.length; index += 1) {
    if (
      messageSignature(prefix[index]) !==
      messageSignature(messages[index])
    ) {
      return false;
    }
  }
  return true;
}

function hasAssistantPreamble(messages) {
  for (const message of messages.slice(0, 16)) {
    if (message?.role === "assistant") {
      return true;
    }
    if (message?.role === "user") {
      return false;
    }
  }
  return false;
}

function hasRetainedConversation(state) {
  return Boolean(
    state.memory ||
      state.compactionCheckpoint ||
      (Array.isArray(state.messages) && state.messages.length),
  );
}

function resetConversationState(state) {
  return {
    ...state,
    memory: null,
    compactionCheckpoint: null,
    messages: [],
    compactionFailures: 0,
    compactionBackoffUntil: 0,
    storageOverflow: false,
  };
}

export function reconcileRoleplayHistory({
  state,
  parsed,
  incomingMessages,
  checkpointMatched,
}) {
  const storedMessages = Array.isArray(state.messages)
    ? state.messages
    : [];
  const authoritativeSnapshot = Boolean(
    parsed.authoritativeHistorySnapshot ||
      hasAssistantPreamble(incomingMessages),
  );
  const continuesStoredHistory = storedMessages.length
    ? isPrefix(storedMessages, incomingMessages)
    : checkpointMatched;
  const retainedConversation = hasRetainedConversation(state);
  const reset =
    retainedConversation &&
    (parsed.historyMode === "replace" ||
      (parsed.historyMode === "auto" &&
        authoritativeSnapshot &&
        !continuesStoredHistory));

  return {
    reset,
    state: reset ? resetConversationState(state) : state,
  };
}
