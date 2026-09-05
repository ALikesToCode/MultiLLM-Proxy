import { action, api, element, sessionQuery, status } from "./api.mjs";
import { consumeStream } from "./stream.mjs";

export function initSessions() {
  let monitoring = false, epoch = 0, timer, poll, revision = null, inspectedScope = null;
  let recovery = null, recoveryScope = null, generation = null;
  const stop = () => {
    monitoring = false; epoch++; clearTimeout(timer); poll?.abort();
    element("timeline-status").textContent = "Monitoring stopped. No generation was started.";
  };
  const clearPrivate = () => {
    generation?.abort();
    stop(); revision = null; inspectedScope = null; recovery = null; recoveryScope = null;
    element("memory-editor").hidden = true;
    for (const id of ["memory-summary", "memory-pins"]) element(id).value = "";
    for (const id of ["retained-context", "branch-result", "timeline-result", "recovery-output", "recovery-status"]) element(id).textContent = "";
    element("recovery-continue").disabled = true; element("recovery-regenerate").disabled = true;
  };
  for (const id of ["session-id", "session-scope"]) {
    element(id).addEventListener("change", clearPrivate);
    element(id).addEventListener("input", clearPrivate);
  }
  document.addEventListener("visibilitychange", () => { if (document.hidden) stop(); });
  window.addEventListener("pagehide", () => { stop(); generation?.abort(); });
  const renderTimeline = (data) => {
    const target = element("timeline-result"); target.replaceChildren();
    for (const row of [...data.records].reverse()) {
      const article = document.createElement("article"); article.className = "wb-answer";
      const title = document.createElement("h3"); title.textContent = `${row.phase} · ${row.provider || "route pending"}${row.model ? " / " + row.model : ""}`;
      const events = document.createElement("p");
      events.textContent = row.events.map((event) => `${event.phase} ${(event.elapsedMs / 1000).toFixed(2)}s`).join(" → ");
      const details = document.createElement("details"), summary = document.createElement("summary"), receipt = document.createElement("pre");
      summary.textContent = "Timing, trace ID & effective parameters";
      receipt.textContent = JSON.stringify({ id: row.id, metrics: row.metrics, parameters: row.parameters, reason: row.reason }, null, 2);
      details.append(summary, receipt); article.append(title, events, details); target.append(article);
    }
    element("timeline-status").textContent = `${data.records.length} turns. ${data.retention}. Times are observed events, not advertised provider TPS.`;
  };
  const monitor = async (query, currentEpoch) => {
    poll = new AbortController();
    try {
      const data = await api("timeline?" + query, undefined, { signal: poll.signal });
      if (monitoring && currentEpoch === epoch && sessionQuery() === query) renderTimeline(data);
    } catch (error) {
      if (error.name !== "AbortError" && monitoring && currentEpoch === epoch) element("timeline-status").textContent = `${error.message} Diagnostics will reconnect; no generation will be retried.`;
    } finally {
      if (monitoring && currentEpoch === epoch) timer = setTimeout(() => monitor(query, currentEpoch), 3000);
    }
  };
  action("timeline-start", async () => {
    const query = sessionQuery(); stop(); monitoring = true;
    element("timeline-status").textContent = "Connecting diagnostics…";
    await monitor(query, epoch);
  });
  element("timeline-stop").addEventListener("click", stop);
  const displayMemory = (data, query) => {
    revision = data.revision; inspectedScope = query;
    element("memory-editor").hidden = false;
    element("memory-revision").textContent = `Revision ${revision} · ${data.retainedMessageCount} retained messages · ${data.completedTurns} completed turns`;
    element("memory-summary").value = data.memory?.summary || "";
    element("memory-pins").value = data.pins.join("\n");
    element("retained-context").textContent = JSON.stringify({ memory: data.memory, profile: data.profile, branch: data.branch,
      ...(data.retainedMessages ? { retainedMessages: data.retainedMessages, protectedDirectives: data.protectedDirectives } : {}) }, null, 2);
  };
  action("memory-inspect", async () => {
    const query = sessionQuery();
    const data = await api("memory?" + query, { action: "inspect", include_context: element("include-context").checked });
    if (sessionQuery() === query) displayMemory(data, query);
  });
  const checkedRevision = () => {
    const query = sessionQuery();
    if (!revision || inspectedScope !== query) throw new Error("Inspect the selected session before changing it.");
    return query;
  };
  action("memory-save", async () => {
    const query = checkedRevision();
    const data = await api("memory?" + query, { action: "update", revision,
      summary: element("memory-summary").value, pins: element("memory-pins").value.split("\n").map((pin) => pin.trim()).filter(Boolean) });
    if (sessionQuery() === query) displayMemory(data, query);
    status("Corrections saved. Stale revisions are rejected, never silently overwritten.");
  });
  action("branch-create", async () => {
    const query = checkedRevision();
    if (!window.confirm("Copy this session's retained private context into a new independent branch? The original is preserved. This does not generate a reply.")) return;
    const result = await api("branch?" + query, { revision, label: element("branch-label").value.trim(), confirm: true });
    if (sessionQuery() === query) element("branch-result").textContent = `Branch ${result.label}: ${result.session_id}. Use this new session ID to continue separately.`;
  });
  action("recovery-inspect", async () => {
    const query = sessionQuery();
    const result = await api("recovery?" + query, { action: "inspect" });
    if (sessionQuery() !== query) return;
    recovery = result; recoveryScope = query;
    element("recovery-output").textContent = result.partial || "No visible partial was retained.";
    element("recovery-status").textContent = `${result.reason} · available until ${new Date(result.expiresAt).toLocaleString()}${result.truncated ? " · partial truncated; regenerate only" : ""}`;
    element("recovery-continue").disabled = !result.partial?.trim() || result.truncated;
    element("recovery-regenerate").disabled = false;
  });
  const recover = async (mode) => {
    const query = sessionQuery();
    if (generation || !recovery || recoveryScope !== query) throw new Error("Inspect the selected session's recovery snapshot first.");
    if (!window.confirm(`${mode === "continue" ? "Continue the partial" : "Regenerate the turn"}? This consumes the recovery snapshot once and starts a potentially billed generation in a new session. Network failure will not automatically retry it.`)) return;
    const token = recovery.token, partial = mode === "continue" ? recovery.partial : "";
    recovery = null; generation = new AbortController();
    for (const id of ["recovery-continue", "recovery-regenerate", "recovery-inspect", "session-id", "session-scope"]) element(id).disabled = true;
    element("recovery-stop").disabled = false;
    element("recovery-status").textContent = "Starting one new generation…";
    const startedAt = performance.now();
    try {
      const response = await api("recovery?" + query, { action: mode, token, confirm: true }, { signal: generation.signal, stream: true });
      const id = response.headers.get("X-Roleplay-Session-ID");
      const result = await consumeStream(response, { signal: generation.signal, startedAt,
        onText: (text) => { element("recovery-output").textContent = partial + text; } });
      element("recovery-status").textContent = `${result.message} New session: ${id || "unavailable"}. The original session is unchanged.`;
    } catch (error) { element("recovery-status").textContent = `${error.message} No automatic retry. Inspect before taking another action.`; }
    finally {
      generation = null; element("recovery-stop").disabled = true;
      for (const id of ["recovery-inspect", "session-id", "session-scope"]) element(id).disabled = false;
    }
  };
  for (const mode of ["continue", "regenerate"]) element("recovery-" + mode).addEventListener("click", () => { void recover(mode).catch((error) => status(error.message)); });
  element("recovery-stop").addEventListener("click", () => generation?.abort());
}
