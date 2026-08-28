import { RoleplayRequestError } from "./validation.mjs";

const MODEL_PREFERENCES = new Set([
  "auto",
  "speed",
  "kimi",
  "glm",
  "glm-5.2",
  "glm-5.3-flash",
  "glm-5.3",
  "uncensored",
]);

const REQUEST_MODEL_ALIASES = Object.freeze({
  auto: "auto",
  speed: "speed",
  kimi: "kimi",
  glm: "glm",
  roleplay: "auto",
  "roleplay:auto": "auto",
  "roleplay:speed": "speed",
  "roleplay:kimi": "kimi",
  "roleplay:glm": "glm",
  "roleplay:5.2": "glm-5.2",
  "roleplay:glm-5.2": "glm-5.2",
  "roleplay:5.3-flash": "glm-5.3-flash",
  "roleplay:glm-5.3-flash": "glm-5.3-flash",
  "roleplay:5.3": "glm-5.3",
  "roleplay:glm-5.3": "glm-5.3",
  "roleplay:uncensored": "uncensored",
  "kimi-k2.6": "kimi",
  "glm-5.2": "glm-5.2",
  "glm-5.3-flash": "glm-5.3-flash",
  "glm-5.3": "glm-5.3",
});

export const ROLEPLAY_PUBLIC_MODEL_ALIASES = Object.freeze({
  "roleplay:auto": "adaptive stable models",
  "roleplay:speed": "adaptive stable models",
  "roleplay:kimi": "Kimi family",
  "roleplay:glm": "GLM-5.3-Flash with a measured 20% full-model latency guard",
  "roleplay:5.3-flash": "GLM-5.3-Flash only",
  "roleplay:5.3": "full GLM-5.3 only",
  "roleplay:5.2": "GLM-5.2 only",
  "roleplay:uncensored": "uncensored GLM route with GLM-5.2 Venice fallback",
});

function normalizedPreference(value) {
  const normalized =
    typeof value === "string" ? value.trim().toLowerCase() : "";
  if (["5.2", "5.3", "5.3-flash"].includes(normalized)) {
    return `glm-${normalized}`;
  }
  return normalized;
}

export function parseRoleplayModelPreference(payload) {
  const explicit = normalizedPreference(payload.model_preference);
  if (explicit) {
    if (!MODEL_PREFERENCES.has(explicit)) {
      throw new RoleplayRequestError(
        "model_preference must be auto, speed, kimi, glm, glm-5.3-flash, glm-5.3, glm-5.2, or uncensored",
      );
    }
    return explicit;
  }

  const model = normalizedPreference(payload.model);
  if (REQUEST_MODEL_ALIASES[model]) {
    return REQUEST_MODEL_ALIASES[model];
  }
  if (model.startsWith("roleplay:")) {
    throw new RoleplayRequestError(
      "model must be roleplay:auto, roleplay:speed, roleplay:kimi, roleplay:glm, roleplay:5.3-flash, roleplay:5.3, roleplay:5.2, or roleplay:uncensored",
    );
  }
  return "auto";
}

function glmModelVersion(model) {
  const match = String(model ?? "").match(
    /(?:^|\/)glm[-_]?([0-9]+\.[0-9]+)/i,
  );
  return match?.[1] ?? "";
}

export function glmModelVariant(model) {
  const normalized = String(model ?? "").toLowerCase();
  const explicitUncensored = normalized.includes("uncensored");
  const venice = normalized.includes("venice");
  return {
    version: glmModelVersion(normalized),
    flash: /glm[-_]?5\.3[-_:]?flash/.test(normalized),
    uncensored: explicitUncensored || venice,
    explicitUncensored,
    venice,
  };
}

export function roleplayCandidateMatchesPreference(candidate, preference) {
  const normalized = normalizedPreference(preference) || "auto";
  const explicitGlmVersion = normalized.match(/^glm-([0-9]+\.[0-9]+)$/)?.[1];

  if (normalized === "kimi") {
    return candidate.family === "kimi";
  }
  if (
    normalized === "glm" ||
    normalized === "glm-5.3-flash" ||
    normalized === "uncensored" ||
    explicitGlmVersion
  ) {
    if (candidate.family !== "glm") {
      return false;
    }
  } else if (candidate.family !== "kimi" && candidate.family !== "glm") {
    return false;
  }

  if (candidate.family !== "glm") {
    return true;
  }
  const variant = glmModelVariant(candidate.model);
  if (normalized === "uncensored") {
    return variant.uncensored;
  }
  if (variant.explicitUncensored) {
    return false;
  }
  if (normalized === "glm-5.3-flash") {
    return variant.version === "5.3" && variant.flash;
  }
  if (explicitGlmVersion) {
    return (
      variant.version === explicitGlmVersion &&
      (explicitGlmVersion !== "5.3" || !variant.flash)
    );
  }
  return !variant.version || ["5.3", "5.2"].includes(variant.version);
}
