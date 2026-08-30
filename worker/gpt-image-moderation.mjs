const GPT_IMAGE_MODEL_FAMILIES = Object.freeze([
  "gpt-image-1",
  "gpt-image-1-mini",
  "gpt-image-1.5",
  "gpt-image-2",
]);
const GPT_IMAGE_MODERATION_VALUES = new Set(["auto", "low"]);

export class GPTImageModerationError extends Error {
  constructor() {
    super("GPT Image moderation must be one of: auto, low");
    this.name = "GPTImageModerationError";
  }
}

export function isGptImageModel(modelId) {
  let normalized = typeof modelId === "string" ? modelId.trim().toLowerCase() : "";
  if (!normalized) {
    return false;
  }
  if (normalized.includes(":")) {
    normalized = normalized.split(":", 2)[1];
  }
  const basename = normalized.split("/").at(-1) ?? "";
  return GPT_IMAGE_MODEL_FAMILIES.some(
    (family) => basename === family || basename.startsWith(`${family}-`),
  );
}

export function applyGptImageModerationDefault(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return { payload, changed: false };
  }
  if (!isGptImageModel(payload.model)) {
    return { payload, changed: false };
  }
  if (payload.moderation != null) {
    if (!GPT_IMAGE_MODERATION_VALUES.has(payload.moderation)) {
      throw new GPTImageModerationError();
    }
    return { payload, changed: false };
  }
  return {
    payload: { ...payload, moderation: "low" },
    changed: true,
  };
}

export async function withDefaultGptImageModeration(request, upstreamPath) {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (
    request.method !== "POST" ||
    upstreamPath.toLowerCase() !== "/v1/images/generations" ||
    !contentType.startsWith("application/json")
  ) {
    return request;
  }

  let payload;
  try {
    payload = await request.clone().json();
  } catch {
    return request;
  }
  const decision = applyGptImageModerationDefault(payload);
  if (!decision.changed) {
    return request;
  }

  const headers = new Headers(request.headers);
  headers.delete("content-length");
  return new Request(request, {
    headers,
    body: JSON.stringify(decision.payload),
    duplex: "half",
  });
}
