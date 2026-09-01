import { RoleplayRequestError } from "./validation.mjs";

const MODEL_PREFERENCES = new Set([
  "auto",
  "speed",
  "kimi",
  "glm",
  "glm-speed",
  "glm-5.2",
  "glm-5.3-flash",
  "glm-5.3-flash-uncensored",
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
  "roleplay:glm-speed": "glm-speed",
  "roleplay:5.2": "glm-5.2",
  "roleplay:glm-5.2": "glm-5.2",
  "roleplay:5.3-flash": "glm-5.3-flash",
  "roleplay:glm-5.3-flash": "glm-5.3-flash",
  "roleplay:5.3-flash-uncensored": "glm-5.3-flash-uncensored",
  "roleplay:glm-5.3-flash-uncensored": "glm-5.3-flash-uncensored",
  "roleplay:5.3": "glm-5.3",
  "roleplay:glm-5.3": "glm-5.3",
  "roleplay:uncensored": "uncensored",
  "kimi-k2.6": "kimi",
  "z-ai/glm-5.3-flash": "glm-5.3-flash",
  "z-ai/glm-5.3-flash-uncensored": "glm-5.3-flash-uncensored",
  "z-ai/glm-5.3": "glm-5.3",
  "zai-org/glm-5.2": "glm-5.2",
  "zai-org/glm-5.2:thinking": "glm-5.2",
  "glm-5.2": "glm-5.2",
  "glm-5.3-flash": "glm-5.3-flash",
  "glm-5.3": "glm-5.3",
});

export const ROLEPLAY_PUBLIC_MODEL_ALIASES = Object.freeze({
  "roleplay:auto": "adaptive stable models",
  "roleplay:speed": "adaptive stable models",
  "roleplay:kimi": "Kimi family",
  "roleplay:glm": "subscription-safe GLM quality order: 5.3 Flash, uncensored Flash, then 5.2",
  "roleplay:glm-speed": "subscription-safe GLM pool ranked by measured streaming TPS",
  "roleplay:5.3-flash": "GLM-5.3-Flash only",
  "roleplay:5.3-flash-uncensored": "GLM-5.3-Flash Uncensored only",
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
        "model_preference must be auto, speed, kimi, glm, glm-speed, glm-5.3-flash, glm-5.3-flash-uncensored, glm-5.3, glm-5.2, or uncensored",
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
      "model must be roleplay:auto, roleplay:speed, roleplay:kimi, roleplay:glm, roleplay:glm-speed, roleplay:5.3-flash, roleplay:5.3-flash-uncensored, roleplay:5.3, roleplay:5.2, or roleplay:uncensored",
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
    normalized === "glm-speed" ||
    normalized === "glm-5.3-flash" ||
    normalized === "glm-5.3-flash-uncensored" ||
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
  if (normalized === "glm-5.3-flash") {
    return variant.version === "5.3" && variant.flash && !variant.uncensored;
  }
  if (normalized === "glm-5.3-flash-uncensored") {
    return (
      variant.version === "5.3" &&
      variant.flash &&
      variant.explicitUncensored
    );
  }
  if (explicitGlmVersion) {
    return (
      variant.version === explicitGlmVersion &&
      (explicitGlmVersion !== "5.3" || !variant.flash)
    );
  }
  if (normalized === "glm-speed") {
    return (
      variant.explicitUncensored ||
      variant.version === "5.2" ||
      (variant.version === "5.3" && variant.flash)
    );
  }
  if (
    candidate.subscriptionOnly &&
    variant.version === "5.3" &&
    !variant.flash
  ) {
    return false;
  }
  return !variant.version || ["5.3", "5.2"].includes(variant.version);
}
