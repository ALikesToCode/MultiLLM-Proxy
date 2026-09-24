import { api, queryPayload, sourcePayload } from "./api.mjs";
import { element, renderReadiness, renderSources, renderJobs, renderUsage, renderEvidence } from "./render.mjs";
import { renderPolicy, policyPayload } from "./policy.mjs";
import { initializeAlexandria } from "./alexandria.mjs";

let serviceConnected = false;
let statusInFlight = false;
let policyDirty = false;

async function loadStatus({ replacePolicy = false } = {}) {
  if (statusInFlight) return;
  statusInFlight = true;
  const banner = element("knowledge-status");
  const refresh = element("knowledge-refresh");
  refresh.disabled = true;
  refresh.setAttribute("aria-busy", "true");
  banner.dataset.state = "loading";
  banner.textContent = "Checking service configuration and stored receipts…";
  try {
    const result = await api("status");
    serviceConnected = Boolean(result.policy);
    banner.textContent = !serviceConnected ? "Setup required: connect the private Knowledge service."
      : result.ready ? "Knowledge is ready for requests within the configured allowances."
        : "Knowledge is connected. Review setup and enable the required allowances to retrieve evidence.";
    banner.dataset.state = result.ready ? "ready" : "setup";
    renderReadiness(result); renderSources(result.sources); renderJobs(result.jobs); renderUsage(result.usage);
    element("knowledge-allowed-hosts").textContent = result.policy
      ? `Approved source hosts: ${result.policy.allowed_hosts.join(", ") || "None"}. Redirect destinations must also be approved.`
      : "Approved hosts are unavailable until the service is connected.";
    if (!policyDirty || replacePolicy) { renderPolicy(result.policy); policyDirty = false; }
    for (const button of document.querySelectorAll("[data-needs-service]")) button.disabled = !serviceConnected || button.dataset.busy === "true";
  } catch (error) {
    banner.textContent = `Knowledge status could not be loaded: ${error.message}`;
    banner.dataset.state = "error";
    if (!serviceConnected) {
      for (const id of ["knowledge-readiness", "knowledge-providers", "knowledge-source-list", "knowledge-jobs", "knowledge-usage"]) element(id).textContent = "Status unavailable. Refresh to try again.";
    }
  } finally {
    statusInFlight = false;
    refresh.disabled = false;
    refresh.removeAttribute("aria-busy");
  }
}

function formAction(id, statusId, callback) {
  element(id).addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    const note = element(statusId);
    submit.dataset.busy = "true";
    submit.disabled = true;
    submit.setAttribute("aria-busy", "true");
    delete note.dataset.tone;
    note.textContent = "Working…";
    try { await callback(form); }
    catch (error) { note.dataset.tone = "error"; note.textContent = error.message; }
    finally { submit.dataset.busy = "false"; submit.disabled = !serviceConnected; submit.removeAttribute("aria-busy"); }
  });
}

element("knowledge-refresh").addEventListener("click", () => loadStatus());
element("knowledge-policy-reload").addEventListener("click", () => loadStatus({ replacePolicy: true }));
element("knowledge-policy-form").addEventListener("input", () => { policyDirty = true; });

formAction("knowledge-query-form", "knowledge-query-status", async (form) => {
  element("knowledge-results").replaceChildren();
  const result = await api("query", { method: "POST", body: queryPayload(new FormData(form)) });
  renderEvidence(result);
  element("knowledge-query-status").textContent = result.status === "ok" ? "Evidence retrieved. Inspect the source and version basis below."
    : result.status === "partial" ? "Partial evidence. Review the coverage gaps before using these excerpts."
      : "Insufficient evidence for the requested question or version.";
});

formAction("knowledge-source-form", "knowledge-source-status", async (form) => {
  const result = await api("sources", { method: "POST", body: sourcePayload(new FormData(form)) });
  element("knowledge-source-status").textContent = `Source saved${result.source?.id ? `: ${result.source.id}` : ""}. Use Refresh source to request acquisition and indexing.`;
  await loadStatus();
});

formAction("knowledge-policy-form", "knowledge-policy-status", async (form) => {
  await api("policy", { method: "PUT", body: policyPayload(new FormData(form), form.dataset.revision) });
  policyDirty = false;
  await loadStatus({ replacePolicy: true });
  element("knowledge-policy-status").textContent = `Policy saved at revision ${form.dataset.revision}. Provider acknowledgements have not been checked live.`;
});

element("knowledge-source-list").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  button.disabled = true;
  const { id, action, revision } = button.dataset;
  try {
    if (action === "refresh") {
      await api(`sources/${encodeURIComponent(id)}/refresh`, { method: "POST", body: {} });
      element("knowledge-source-status").textContent = "Refresh requested. Inspect the job status for progress.";
    } else {
      const body = { expected_revision: Number(revision) };
      if (["enable", "disable"].includes(action)) body.enabled = action === "enable";
      else if (["pin", "unpin"].includes(action)) body.pinned = action === "pin";
      else if (action === "interval") {
        const input = button.closest("article").querySelector("[data-refresh-hours]");
        if (!input.reportValidity()) return;
        body.refresh_hours = Number(input.value);
      }
      else return;
      await api(`sources/${encodeURIComponent(id)}`, { method: "PATCH", body });
      element("knowledge-source-status").textContent = "Source settings saved.";
    }
    await loadStatus();
  } catch (error) { element("knowledge-source-status").textContent = error.message; }
  finally { button.disabled = false; }
});

element("knowledge-jobs").addEventListener("click", async (event) => {
  const button = event.target.closest('button[data-action="cancel"]');
  if (!button) return;
  button.disabled = true;
  try {
    await api(`jobs/${encodeURIComponent(button.dataset.id)}/cancel`, { method: "POST", body: {} });
    element("knowledge-job-status").textContent = "Cancellation requested. Already accepted upstream work cannot be reversed.";
    await loadStatus();
  } catch (error) { element("knowledge-job-status").textContent = error.message; }
  finally { button.disabled = false; }
});

initializeAlexandria(formAction, loadStatus);
await loadStatus();
