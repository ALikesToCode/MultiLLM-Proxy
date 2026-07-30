function messageSignature(message) {
  return JSON.stringify([
    message.role,
    message.name ?? "",
    message.tool_call_id ?? "",
    message.content,
  ]);
}

function stableHistoryAnchor(messages, character) {
  let hasPreamble = Boolean(character?.name);
  for (const message of messages.slice(0, 16)) {
    if (
      ["system", "developer", "assistant"].includes(message.role)
    ) {
      hasPreamble = true;
    }
    if (message.role === "user") {
      return hasPreamble;
    }
  }
  return false;
}

async function compactedPrefixDigest(character, messages) {
  const encoded = new TextEncoder().encode(
    JSON.stringify({
      version: 1,
      character: character?.name ?? "",
      messages: messages.map(messageSignature),
    }),
  );
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoded),
  );
  return Array.from(
    digest,
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}

function contiguousSequenceStart(messages, sequence) {
  if (!sequence.length) {
    return messages.length;
  }
  const messageSignatures = messages.map(messageSignature);
  const sequenceSignatures = sequence.map(messageSignature);
  for (
    let start = messageSignatures.length - sequenceSignatures.length;
    start >= 0;
    start -= 1
  ) {
    let matches = true;
    for (let index = 0; index < sequenceSignatures.length; index += 1) {
      if (
        messageSignatures[start + index] !== sequenceSignatures[index]
      ) {
        matches = false;
        break;
      }
    }
    if (matches) {
      return start;
    }
  }
  return -1;
}

export async function reuseCompactionCheckpoint(state, parsed) {
  const sourceMessages = parsed.messages;
  const checkpoint = state.compactionCheckpoint;
  if (
    parsed.memory.mode === "off" ||
    parsed.historyMode !== "auto" ||
    !checkpoint ||
    checkpoint.version !== 1 ||
    !Number.isInteger(checkpoint.messageCount) ||
    checkpoint.messageCount < 1 ||
    checkpoint.messageCount > sourceMessages.length ||
    !/^[a-f0-9]{64}$/.test(checkpoint.digest ?? "")
  ) {
    return { parsed, sourceMessages, matched: false };
  }

  const prefix = sourceMessages.slice(0, checkpoint.messageCount);
  const digest = await compactedPrefixDigest(parsed.character, prefix);
  if (digest !== checkpoint.digest) {
    return { parsed, sourceMessages, matched: false };
  }
  return {
    parsed: {
      ...parsed,
      messages: sourceMessages.slice(checkpoint.messageCount),
    },
    sourceMessages,
    matched: true,
  };
}

export async function createCompactionCheckpoint(
  state,
  parsed,
  sourceMessages,
  plan,
  previousMatched,
) {
  const previous = state.compactionCheckpoint ?? null;
  if (
    !previousMatched &&
    !stableHistoryAnchor(sourceMessages, parsed.character)
  ) {
    return previous;
  }

  const boundary = contiguousSequenceStart(
    sourceMessages,
    plan.recentMessages,
  );
  if (
    boundary < 1 ||
    (previousMatched &&
      boundary < (previous?.messageCount ?? 0))
  ) {
    return previous;
  }

  return {
    version: 1,
    messageCount: boundary,
    digest: await compactedPrefixDigest(
      parsed.character,
      sourceMessages.slice(0, boundary),
    ),
  };
}
