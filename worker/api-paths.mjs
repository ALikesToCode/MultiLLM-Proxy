// API namespaces shared by edge preflight and error handling.

const API_ROUTE_PREFIXES = new Set([
  "aihubmix",
  "azure",
  "cerebras",
  "chutes",
  "codex-easy",
  "gemini",
  "gemma",
  "googleai",
  "groq",
  "hyperbolic",
  "intelligence",
  "kimi-code",
  "linkapi",
  "mimo",
  "nanogpt",
  "navyai",
  "nineteen",
  "openai",
  "opencode",
  "openrouter",
  "optimize",
  "palm",
  "roleplay",
  "sambanova",
  "scaleway",
  "together",
  "v1",
  "xai",
]);

export function isApiRequestPath(pathname) {
  const stripped = pathname.replace(/^\/+|\/+$/g, "");
  if (!stripped) {
    return false;
  }

  if (stripped === "health" || stripped === "ready") {
    return true;
  }

  const [firstSegment] = stripped.split("/", 1);
  return API_ROUTE_PREFIXES.has(firstSegment);
}
