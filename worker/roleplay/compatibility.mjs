export const ROLEPLAY_PATH = "/v1/roleplay";
export const ROLEPLAY_CHAT_COMPLETIONS_PATH =
  "/v1/roleplay/chat/completions";
export const ROLEPLAY_JANITOR_PATH =
  "/roleplay/v1/chat/completions";
export const ROLEPLAY_MODELS_PATH = "/v1/roleplay/models";
export const ROLEPLAY_METRICS_PATH = "/v1/roleplay/metrics";

const ROLEPLAY_TURN_PATHS = new Set([
  ROLEPLAY_PATH,
  ROLEPLAY_CHAT_COMPLETIONS_PATH,
  ROLEPLAY_JANITOR_PATH,
]);
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{8,128}$/;
const CLIENT_ID_FIELDS = [
  "conversation_id",
  "conversationId",
  "chat_id",
  "chatId",
  "thread_id",
  "threadId",
];

function scalarIdentifier(value) {
  if (typeof value === "string" && value.trim()) {
    return value.trim();
  }
  if (Number.isSafeInteger(value)) {
    return String(value);
  }
  return "";
}

function clientConversationIdentifier(payload) {
  for (const field of CLIENT_ID_FIELDS) {
    const value = scalarIdentifier(payload?.[field]);
    if (value) {
      return { field, value };
    }
  }

  const metadata =
    payload?.metadata &&
    typeof payload.metadata === "object" &&
    !Array.isArray(payload.metadata)
      ? payload.metadata
      : {};
  for (const field of ["session_id", ...CLIENT_ID_FIELDS]) {
    const value = scalarIdentifier(metadata[field]);
    if (value) {
      return { field: `metadata.${field}`, value };
    }
  }
  return null;
}

function normalizedAnchorMessage(message) {
  if (
    !message ||
    typeof message !== "object" ||
    Array.isArray(message) ||
    typeof message.role !== "string" ||
    typeof message.content !== "string"
  ) {
    return null;
  }
  const role = message.role.trim().toLowerCase();
  const content = message.content.trim();
  if (
    !["system", "developer", "assistant", "user"].includes(role) ||
    !content
  ) {
    return null;
  }
  return {
    role,
    name:
      typeof message.name === "string" ? message.name.trim() : "",
    content,
  };
}

function conversationAnchor(payload) {
  if (!Array.isArray(payload?.messages)) {
    return null;
  }

  const opening = [];
  let foundUser = false;
  for (const message of payload.messages.slice(0, 16)) {
    const normalized = normalizedAnchorMessage(message);
    if (!normalized) {
      continue;
    }
    opening.push(normalized);
    if (normalized.role === "user") {
      foundUser = true;
      break;
    }
  }

  const hasPreamble = opening.some((message) =>
    ["system", "developer", "assistant"].includes(message.role),
  );
  if (!foundUser || !hasPreamble) {
    return null;
  }
  return {
    opening,
    user:
      scalarIdentifier(payload.user) ||
      scalarIdentifier(payload?.metadata?.user_id),
  };
}

async function digestSessionName(kind, scopeToken, value) {
  const encoded = new TextEncoder().encode(
    JSON.stringify({
      version: 1,
      kind,
      scope: scopeToken,
      value,
    }),
  );
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoded),
  );
  const hex = Array.from(
    digest,
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
  return `rp_${hex}`;
}

async function timingSafeTokenMatch(providedToken, expectedToken) {
  const encoder = new TextEncoder();
  const [providedDigest, expectedDigest] = await Promise.all([
    crypto.subtle.digest(
      "SHA-256",
      encoder.encode(String(providedToken ?? "")),
    ),
    crypto.subtle.digest(
      "SHA-256",
      encoder.encode(String(expectedToken ?? "")),
    ),
  ]);
  const providedBytes = new Uint8Array(providedDigest);
  const expectedBytes = new Uint8Array(expectedDigest);

  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return (
      Boolean(providedToken) &&
      Boolean(expectedToken) &&
      crypto.subtle.timingSafeEqual(providedBytes, expectedBytes)
    );
  }

  let mismatch = providedBytes.byteLength ^ expectedBytes.byteLength;
  for (let index = 0; index < providedBytes.byteLength; index += 1) {
    mismatch |= providedBytes[index] ^ expectedBytes[index];
  }
  return Boolean(providedToken) && Boolean(expectedToken) && mismatch === 0;
}

export function extractBearerToken(request) {
  const authorization = request.headers.get("Authorization") ?? "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() ?? "";
}

export function hasRoleplayAuthentication(env) {
  return Boolean(env.ROLEPLAY_API_KEY || env.ADMIN_API_KEY);
}

export async function isAuthorizedRoleplayToken(providedToken, env) {
  const [roleplayMatch, adminMatch] = await Promise.all([
    timingSafeTokenMatch(providedToken, env.ROLEPLAY_API_KEY),
    timingSafeTokenMatch(providedToken, env.ADMIN_API_KEY),
  ]);
  return roleplayMatch || adminMatch;
}

export function isValidRoleplaySessionId(value) {
  return typeof value === "string" && SESSION_ID_PATTERN.test(value);
}

export function isRoleplayPath(pathname) {
  return (
    ROLEPLAY_TURN_PATHS.has(pathname) ||
    pathname === ROLEPLAY_MODELS_PATH ||
    pathname === ROLEPLAY_METRICS_PATH
  );
}

export function isRoleplayTurnPath(pathname) {
  return ROLEPLAY_TURN_PATHS.has(pathname);
}

export async function resolveRoleplaySession(
  payload,
  request,
  scopeToken,
) {
  const headerValue = request.headers.get("X-Roleplay-Session-ID");
  const explicit =
    typeof headerValue === "string" && headerValue.trim()
      ? headerValue.trim()
      : payload?.session_id;
  if (explicit !== undefined && explicit !== null && explicit !== "") {
    if (!isValidRoleplaySessionId(explicit)) {
      return {
        error:
          "session_id must contain 8-128 letters, digits, underscores, or hyphens",
      };
    }
    return { id: explicit, source: "explicit" };
  }

  const clientIdentifier = clientConversationIdentifier(payload);
  if (clientIdentifier) {
    return {
      id: await digestSessionName(
        "client",
        scopeToken,
        clientIdentifier,
      ),
      source: "client",
    };
  }

  const anchor = conversationAnchor(payload);
  if (anchor) {
    return {
      id: await digestSessionName("anchor", scopeToken, anchor),
      source: "derived",
    };
  }

  return { id: crypto.randomUUID(), source: "generated" };
}

export function responseWithRoleplaySession(
  response,
  sessionId,
  source,
) {
  const decorated = new Response(response.body, response);
  decorated.headers.set("X-Roleplay-Session-ID", sessionId);
  decorated.headers.set("X-Roleplay-Session-Source", source);
  return decorated;
}
