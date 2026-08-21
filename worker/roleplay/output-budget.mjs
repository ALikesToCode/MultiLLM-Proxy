import { RoleplayRequestError } from "./validation.mjs";

export const UNLIMITED_OUTPUT_SENTINEL = 1_000_000;

const OUTPUT_MODES = new Set(["bounded", "unlimited"]);

function requestedOutputMode(payload) {
  if (payload.output_mode === undefined) {
    return "";
  }
  if (typeof payload.output_mode !== "string") {
    throw new RoleplayRequestError(
      "output_mode must be bounded or unlimited",
    );
  }
  const mode = payload.output_mode.trim().toLowerCase();
  if (!OUTPUT_MODES.has(mode)) {
    throw new RoleplayRequestError(
      "output_mode must be bounded or unlimited",
    );
  }
  return mode;
}

export function parseRoleplayOutputBudget(
  payload,
  { forceUnlimited = false } = {},
) {
  const requestedMode = requestedOutputMode(payload);
  const requested = payload.max_tokens;
  const sentinelUnlimited =
    requested === null ||
    (Number.isSafeInteger(requested) &&
      requested >= UNLIMITED_OUTPUT_SENTINEL);
  const unlimited =
    forceUnlimited || requestedMode === "unlimited" || sentinelUnlimited;

  if (unlimited) {
    return {
      maxTokens: null,
      mode: "unlimited",
      requestedMaxTokens:
        Number.isSafeInteger(requested) && requested > 0
          ? requested
          : null,
    };
  }

  if (requested === undefined) {
    return {
      maxTokens: null,
      mode: "provider_max",
      requestedMaxTokens: null,
    };
  }
  if (!Number.isSafeInteger(requested) || requested < 1) {
    throw new RoleplayRequestError(
      "max_tokens must be a positive safe integer",
    );
  }
  return {
    maxTokens: requested,
    mode: "bounded",
    requestedMaxTokens: requested,
  };
}
