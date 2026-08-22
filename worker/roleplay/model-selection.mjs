import { RoleplayRequestError } from "./validation.mjs";

const MODEL_PREFERENCES = new Set([
  "auto",
  "speed",
  "kimi",
  "glm",
  "glm-5.2",
  "glm-5.3",
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
  "roleplay:5.3": "glm-5.3",
  "roleplay:glm-5.3": "glm-5.3",
  "kimi-k2.6": "kimi",
  "glm-5.2": "glm-5.2",
  "glm-5.3": "glm-5.3",
});

export const ROLEPLAY_PUBLIC_MODEL_ALIASES = Object.freeze({
  "roleplay:auto": "adaptive stable models",
  "roleplay:speed": "adaptive stable models",
  "roleplay:kimi": "Kimi family",
  "roleplay:glm": "GLM-5.2 stable default",
  "roleplay:5.2": "GLM-5.2 only",
  "roleplay:5.3": "GLM-5.3 only (experimental)",
});

function normalizedPreference(value) {
  const normalized =
    typeof value === "string" ? value.trim().toLowerCase() : "";
  if (normalized === "5.2" || normalized === "5.3") {
    return `glm-${normalized}`;
  }
  return normalized;
}

export function parseRoleplayModelPreference(payload) {
  const explicit = normalizedPreference(payload.model_preference);
  if (explicit) {
    if (!MODEL_PREFERENCES.has(explicit)) {
      throw new RoleplayRequestError(
        "model_preference must be auto, speed, kimi, glm, glm-5.2, or glm-5.3",
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
      "model must be roleplay:auto, roleplay:speed, roleplay:kimi, roleplay:glm, roleplay:5.2, or roleplay:5.3",
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

export function roleplayCandidateMatchesPreference(candidate, preference) {
  const normalized = normalizedPreference(preference) || "auto";
  const explicitGlmVersion = normalized.match(
    /^glm-([0-9]+\.[0-9]+)$/,
  )?.[1];

  if (normalized === "kimi") {
    return candidate.family === "kimi";
  }
  if (normalized === "glm" || explicitGlmVersion) {
    if (candidate.family !== "glm") {
      return false;
    }
  } else if (candidate.family !== "kimi" && candidate.family !== "glm") {
    return false;
  }

  if (candidate.family !== "glm") {
    return true;
  }
  const version = glmModelVersion(candidate.model);
  if (explicitGlmVersion) {
    return version === explicitGlmVersion;
  }
  return !version || version === "5.2";
}
