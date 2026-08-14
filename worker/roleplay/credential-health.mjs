import { buildProviderHeaders } from "./config.mjs";

const DEFINITE_KEY_FAILURES = new Set([401, 403, 429]);

function uniqueNanoCredentials(candidates) {
  const seen = new Set();
  return candidates.filter((candidate) => {
    if (
      candidate.provider !== "nanogpt" ||
      seen.has(candidate.credentialId)
    ) {
      return false;
    }
    seen.add(candidate.credentialId);
    return true;
  });
}

function checkedState(state, activeCredential, credentialId = "") {
  const activeCredentials = { ...(state.activeCredentials ?? {}) };
  const credentialUses = {
    ...(state.credentialUses ?? {}),
    nanogpt: { ...(state.credentialUses?.nanogpt ?? {}) },
  };
  if (activeCredential) {
    activeCredentials.nanogpt = activeCredential;
    credentialUses.nanogpt[activeCredential] = 0;
  } else {
    delete activeCredentials.nanogpt;
    if (credentialId) {
      credentialUses.nanogpt[credentialId] = 0;
    }
  }
  return {
    ...state,
    activeCredentials,
    credentialUses,
    nanogptCredentialChecks: (state.nanogptCredentialChecks ?? 0) + 1,
  };
}

async function probeCredential(candidate, env, settings, signal) {
  const controller = new AbortController();
  const forwardAbort = () => controller.abort(signal?.reason);
  if (signal?.aborted) {
    forwardAbort();
  } else {
    signal?.addEventListener("abort", forwardAbort, { once: true });
  }
  const timeout = setTimeout(
    () => controller.abort("nanogpt_key_check_timeout"),
    settings.nanogptKeyCheckTimeoutMs,
  );
  try {
    return await fetch(candidate.catalogEndpoint, {
      method: "GET",
      headers: buildProviderHeaders(candidate, env),
      redirect: "manual",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", forwardAbort);
  }
}

export async function revalidateNanoCredential(
  state,
  candidates,
  env,
  settings,
  signal,
) {
  const credentials = uniqueNanoCredentials(candidates);
  if (!credentials.length) {
    return state;
  }

  const activeCredential = state.activeCredentials?.nanogpt ?? "";
  const activeUses = activeCredential
    ? state.credentialUses?.nanogpt?.[activeCredential] ?? 0
    : 0;
  const shouldCheck =
    (!activeCredential && credentials.length > 1) ||
    activeUses >= settings.nanogptKeyCheckEveryRequests;
  if (!shouldCheck) {
    return state;
  }

  const ordered = [...credentials].sort(
    (left, right) =>
      Number(right.credentialId === activeCredential) -
      Number(left.credentialId === activeCredential),
  );
  for (const candidate of ordered) {
    let response;
    try {
      response = await probeCredential(
        candidate,
        env,
        settings,
        signal,
      );
    } catch {
      return activeCredential
        ? checkedState(state, activeCredential)
        : state;
    }
    try {
      if (response.ok) {
        return checkedState(state, candidate.credentialId);
      }
      if (!DEFINITE_KEY_FAILURES.has(response.status)) {
        return activeCredential
          ? checkedState(state, activeCredential)
          : state;
      }
    } finally {
      await response.body?.cancel();
    }
  }

  return checkedState(state, "", activeCredential);
}
