export const element = (id) => document.getElementById(id);
export function node(tag, text, className) {
  const result = document.createElement(tag);
  if (text !== undefined) result.textContent = String(text);
  if (className) result.className = className;
  return result;
}

export function safeUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password ? url.href : null;
  } catch { return null; }
}

function sourceLink(url, title) {
  const target = safeUrl(url);
  if (!target) return node("span", title || "Source URL unavailable", "card__meta");
  const link = node("a", title || url, "card__link");
  link.href = target;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

function when(value) {
  if (!value) return "Not yet";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

function button(label, action, id, revision) {
  const result = node("button", label, "button button--secondary button--sm");
  result.type = "button";
  result.dataset.action = action;
  result.dataset.id = id;
  if (revision !== undefined) result.dataset.revision = String(revision);
  return result;
}

export function pill(label, tone) { return node("span", label, `status-pill ${tone}`); }

export function card(title, pills = []) {
  const result = node("article", undefined, "card");
  const header = node("div", undefined, "card__header");
  header.append(node("h3", title, "card__title"));
  if (pills.length) {
    const group = node("div", undefined, "card__pills");
    group.append(...pills);
    header.append(group);
  }
  result.append(header);
  return result;
}

function empty(target, message) { target.replaceChildren(node("p", message, "empty-state empty-state--bordered")); }

// Job states come from the Knowledge authority; unknown values stay visibly unknown.
const JOB_TONES = {
  queued: "tone-pending", acquiring: "tone-pending", snapshot: "tone-pending", pending_index: "tone-pending",
  complete: "tone-positive", completed: "tone-positive", failed: "tone-danger",
  cancelled: "tone-neutral", superseded: "tone-neutral",
};

export function renderReadiness(data) {
  const target = element("knowledge-readiness");
  target.replaceChildren();
  for (const item of data.setup || []) {
    const result = card(item.label, [pill(item.configured ? "Configured" : "Setup required", item.configured ? "tone-positive" : "tone-warning")]);
    if (item.detail) result.append(node("p", item.detail, "card__meta"));
    target.append(result);
  }
  if (!target.childNodes.length) empty(target, "No setup checks were returned.");
  const providers = element("knowledge-providers");
  providers.replaceChildren();
  for (const provider of data.providers || []) {
    const pills = [pill(provider.configured ? "configured" : "not configured", provider.configured ? "tone-positive" : "tone-warning")];
    if (provider.enabled !== undefined) pills.push(pill(provider.enabled ? "policy on" : "policy off", provider.enabled ? "tone-info" : "tone-neutral"));
    const result = card(provider.label || provider.id, pills);
    const status = provider.kind === "corpus" ? (provider.configured ? "Service bindings configured" : "Service bindings required") : provider.credential_env
      ? (provider.configured ? "Credential configured" : "Credential required")
      : (provider.configured ? "No provider key required" : "Service binding required");
    result.append(node("p", `${status} · live connection not checked`, "card__meta"));
    if (provider.credential_env) result.append(node("code", provider.credential_env, "card__code"));
    if (provider.configured_key_count) result.append(node("p", `${provider.configured_key_count} configured key${provider.configured_key_count === 1 ? "" : "s · automatic quota failover"}`, "card__meta"));
    const capabilities = Array.isArray(provider.capabilities) ? provider.capabilities.join(", ")
      : Object.entries(provider.capabilities || {}).filter(([, value]) => value).map(([key]) => key).join(", ");
    result.append(node("p", capabilities || provider.kind || "Capabilities unavailable", "card__meta"));
    if (provider.reason || provider.detail) result.append(node("p", provider.reason || provider.detail, "card__meta"));
    if (provider.docs_url) result.append(sourceLink(provider.docs_url, "Provider documentation"));
    providers.append(result);
  }
  if (!providers.childNodes.length) empty(providers, "Connect the Knowledge service to inspect all five provider adapters and AI Search.");
}

export function renderSources(sources) {
  const target = element("knowledge-source-list");
  target.replaceChildren();
  for (const source of sources || []) {
    const pills = [pill(source.enabled ? "enabled" : "disabled", source.enabled ? "tone-positive" : "tone-neutral")];
    if (source.pinned) pills.push(pill("pinned", "tone-info"));
    const result = card(`${source.product} · ${source.version || "Version unspecified"}`, pills);
    result.append(sourceLink(source.url),
      node("p", `${source.provider} · refreshes every ${source.refresh_hours}h · last checked ${when(source.last_checked_at)}`, "card__meta"),
      source.current_artifact
        ? node("p", `Published artifact: ${source.current_artifact}`, "card__meta")
        : node("p", "No published artifact; version coverage is not established.", "callout callout--warning"));
    const actions = node("div", undefined, "card__actions");
    actions.append(button("Refresh source", "refresh", source.id),
      button(source.enabled ? "Disable source" : "Enable source", source.enabled ? "disable" : "enable", source.id, source.revision),
      button(source.pinned ? "Unpin version" : "Pin version", source.pinned ? "unpin" : "pin", source.id, source.revision));
    const schedule = node("label", "Refresh every (hours)", "source-interval");
    const interval = node("input");
    interval.type = "number"; interval.min = "1"; interval.max = "720"; interval.step = "1";
    interval.value = source.refresh_hours; interval.required = true; interval.dataset.refreshHours = "true";
    schedule.append(interval);
    actions.append(schedule, button("Save interval", "interval", source.id, source.revision));
    result.append(actions);
    target.append(result);
  }
  if (!target.childNodes.length) empty(target, "No sources registered. Add a permitted public documentation URL above.");
}

export function renderJobs(jobs) {
  const target = element("knowledge-jobs");
  target.replaceChildren();
  for (const job of jobs || []) {
    const result = card(`Source ${job.source_id}`, [pill(job.status, JOB_TONES[job.status] || "tone-unknown")]);
    result.append(node("p", job.reason || "No additional status detail.", "card__meta"),
      node("p", `Updated ${when(job.updated_at)}`, "card__meta"));
    if (job.artifact_id) result.append(node("p", `Artifact: ${job.artifact_id}`, "card__meta"));
    if (!["complete", "completed", "failed", "cancelled", "superseded"].includes(job.status)) {
      const actions = node("div", undefined, "card__actions");
      actions.append(button("Cancel future work", "cancel", job.id));
      result.append(actions);
    }
    target.append(result);
  }
  if (!target.childNodes.length) empty(target, "No indexing jobs have been created.");
}

export function renderUsage(usage) {
  const target = element("knowledge-usage");
  if (!usage?.length) { empty(target, "No usage receipts are available."); return; }
  const table = node("table", undefined, "data-table");
  const head = node("thead"), labels = node("tr");
  for (const label of ["Provider", "Confirmed", "Pending", "Unknown", "Background", "Total / cap"]) {
    const cell = node("th", label); cell.scope = "col"; labels.append(cell);
  }
  head.append(labels);
  const body = node("tbody");
  for (const item of usage) {
    const row = node("tr");
    const provider = node("th", item.provider ?? "Unknown"); provider.scope = "row";
    row.append(provider);
    for (const value of [item.confirmed, item.pending, item.unknown, item.background, `${item.total} / ${item.limit}`]) row.append(node("td", value ?? "Unknown", "numeric"));
    body.append(row);
  }
  table.append(head, body);
  const shell = node("div", undefined, "table-scroll");
  shell.tabIndex = 0;
  shell.append(table); target.replaceChildren(shell);
}

function excerptCard(excerpt) {
  const result = card(excerpt.title || "Source excerpt");
  result.append(sourceLink(excerpt.url), node("blockquote", excerpt.text, "knowledge-excerpt"));
  const version = excerpt.version || { kind: "unknown" };
  result.append(node("p", `Target match: ${excerpt.target_match || "unverified"} · observed version: ${version.version || "Unknown"} · basis: ${version.kind}`, "card__meta"));
  if (version.proof_url) result.append(sourceLink(version.proof_url, "Version evidence"));
  if (excerpt.locator) result.append(node("p", `Artifact ${excerpt.artifact_id} · UTF-8 bytes ${excerpt.locator.start_byte}–${excerpt.locator.end_byte}`, "card__meta"));
  return result;
}

export function renderEvidence(result) {
  const target = element("knowledge-results");
  target.replaceChildren();
  const summary = node("div", undefined, "evidence-summary");
  summary.append(node("p", `${result.path || "Unknown path"} · ${result.elapsed_ms ?? "Unknown"} ms · ${result.token_count ?? "Unknown"} tokens (${result.token_counting_method || "count unavailable"})`, "card__meta"),
    node("p", `Providers used: ${(result.providers_used || []).join(", ") || "None"}`, "card__meta"));
  target.append(summary);
  for (const gap of result.gaps || []) target.append(node("p", `${gap.code}: ${gap.message}`, "callout callout--warning"));
  for (const excerpt of result.excerpts || []) target.append(excerptCard(excerpt));
  if (!result.excerpts?.length) target.append(node("p", "No qualifying excerpts were found for this request.", "empty-state empty-state--bordered"));
  if (result.related_evidence?.length) {
    const related = node("details", undefined, "knowledge-related");
    related.append(node("summary", `Related evidence with unverified target compatibility (${result.related_evidence.length})`));
    for (const excerpt of result.related_evidence) related.append(excerptCard(excerpt));
    target.append(related);
  }
  if (result.freshness) {
    const detail = node("details", undefined, "knowledge-related");
    detail.append(node("summary", "Freshness and usage receipts"), node("pre", JSON.stringify({ freshness: result.freshness, usage: result.usage || [] }, null, 2), "code-surface"));
    target.append(detail);
  }
}
