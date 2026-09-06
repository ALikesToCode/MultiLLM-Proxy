import { boundedString, RoleplayRequestError } from "./validation.mjs";

const MAX_TOOL_MESSAGE_CHARACTERS = 128_000;
const ALLOWED_ROLES = new Set([
  "system",
  "developer",
  "user",
  "assistant",
  "tool",
]);

function isBlankTextPlaceholder(message, role) {
  // Tool calls, results, and refusals carry meaning even without text.
  if (role === "tool" || ["tool_calls", "function_call", "tool_call_id", "refusal"]
    .some(field => Object.hasOwn(message, field))) {
    return false;
  }
  return message.content === undefined || message.content === null ||
    (typeof message.content === "string" && !message.content.trim());
}

function sanitizeMessage(message, index, maximumCharacters) {
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    throw new RoleplayRequestError(`messages[${index}] must be an object`);
  }
  const role = boundedString(
    message.role,
    `messages[${index}].role`,
    24,
    { required: true },
  ).toLowerCase();
  if (!ALLOWED_ROLES.has(role)) {
    throw new RoleplayRequestError(
      `messages[${index}].role is not supported`,
    );
  }
  if (isBlankTextPlaceholder(message, role)) return null;
  const content = boundedString(
    message.content,
    `messages[${index}].content`,
    role === "tool"
      ? Math.min(maximumCharacters, MAX_TOOL_MESSAGE_CHARACTERS)
      : maximumCharacters,
    { required: true },
  );
  const sanitized = { role, content };
  if (role === "tool") {
    sanitized.tool_call_id = boundedString(
      message.tool_call_id,
      `messages[${index}].tool_call_id`,
      200,
      { required: true },
    );
  }
  if (
    typeof message.name === "string" &&
    message.name.trim() &&
    message.name.length <= 100
  ) {
    sanitized.name = message.name.trim();
  }
  return sanitized;
}

export function sanitizeRoleplayMessages(value, maximumCharacters) {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value) || value.length > 256) {
    throw new RoleplayRequestError(
      "messages must be an array with at most 256 entries",
    );
  }
  return value.map((message, index) =>
    sanitizeMessage(message, index, maximumCharacters),
  ).filter(message => message !== null);
}
