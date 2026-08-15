export const PROVIDER_MESSAGE_FRAGMENT_BYTES = 120_000;

function codePointUtf8Bytes(codePoint) {
  if (codePoint <= 0x7f) {
    return 1;
  }
  if (codePoint <= 0x7ff) {
    return 2;
  }
  if (codePoint <= 0xffff) {
    return 3;
  }
  return 4;
}

export function splitTextByUtf8Bytes(text, maximumBytes) {
  if (typeof text !== "string") {
    return [text];
  }
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 4) {
    throw new RangeError("maximumBytes must be an integer of at least 4");
  }
  if (new TextEncoder().encode(text).byteLength <= maximumBytes) {
    return [text];
  }

  const chunks = [];
  const preferredBreakThreshold = Math.floor(maximumBytes * 0.75);
  let start = 0;
  let index = 0;
  let bytes = 0;
  let preferredBreak = -1;

  while (index < text.length) {
    const codePoint = text.codePointAt(index);
    const width = codePoint > 0xffff ? 2 : 1;
    const codePointBytes = codePointUtf8Bytes(codePoint);
    if (bytes + codePointBytes > maximumBytes) {
      const end = preferredBreak > start ? preferredBreak : index;
      chunks.push(text.slice(start, end));
      start = end;
      index = end;
      bytes = 0;
      preferredBreak = -1;
      continue;
    }

    bytes += codePointBytes;
    index += width;
    if (codePoint === 0x0a && bytes >= preferredBreakThreshold) {
      preferredBreak = index;
    }
  }

  if (start < text.length) {
    chunks.push(text.slice(start));
  }
  return chunks;
}

export function fragmentChatMessages(
  messages,
  maximumBytes = PROVIDER_MESSAGE_FRAGMENT_BYTES,
) {
  if (!Array.isArray(messages)) {
    return messages;
  }

  const fragmented = [];
  let changed = false;
  for (const message of messages) {
    if (
      !message ||
      typeof message !== "object" ||
      message.role === "tool" ||
      typeof message.content !== "string"
    ) {
      fragmented.push(message);
      continue;
    }
    const chunks = splitTextByUtf8Bytes(message.content, maximumBytes);
    if (chunks.length === 1) {
      fragmented.push(message);
      continue;
    }
    changed = true;
    for (const content of chunks) {
      fragmented.push({ ...message, content });
    }
  }
  return changed ? fragmented : messages;
}

export function fragmentChatPayload(
  payload,
  maximumBytes = PROVIDER_MESSAGE_FRAGMENT_BYTES,
) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return payload;
  }
  const messages = fragmentChatMessages(payload.messages, maximumBytes);
  return messages === payload.messages ? payload : { ...payload, messages };
}
