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
  if (!target) return node("span", title || "Source URL unavailable");
  const link = node("a", title || url);
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
  const result = node("button", label, "button button--quiet");
  result.type = "button";
  result.dataset.action = action;
  result.dataset.id = id;
  if (revision !== undefined) result.dataset.revision = String(revision);
  return result;
}

function empty(target, message) { target.replaceChildren(node("p", message, "knowledge-metadata")); }

export function renderReadiness(data) {
  const target = element("knowledge-readiness");
  target.replaceChildren();
  for (const item of data.setup || []) {
    const card = node("article", undefined, "knowledge-card");
    card.append(node("h3", item.label), node("p", item.configured ? "Configured" : "Setup required"),
      node("p", item.detail || "", "knowledge-metadata"));
    target.append(card);
  }
  if (!target.childNodes.length) empty(target, "No setup checks were returned.");
  const providers = element("knowledge-providers");
  providers.replaceChildren();
  for (const provider of data.providers || []) {
    const card = node("article", undefined, "knowledge-card");
    card.append(node("h3", provider.label || provider.id));
    const status = provider.kind === "corpus" ? (provider.configured ? "Service bindings configured" : "Service bindings required") : provider.credential_env
      ? (provider.configured ? "Credential configured" : "Credential required")
      : (provider.configured ? "No provider key required" : "Service binding required");
    card.append(node("p", `${status} · live connection not checked`));
    if (provider.enabled !== undefined) card.append(node("p", provider.enabled ? "Policy enabled" : "Policy disabled", "knowledge-metadata"));
    if (provider.credential_env) card.append(node("code", provider.credential_env));
    if (provider.configured_key_count) card.append(node("p", `${provider.configured_key_count} configured key${provider.configured_key_count === 1 ? "" : "s · automatic quota failover"}`, "knowledge-metadata"));
    const capabilities = Array.isArray(provider.capabilities) ? provider.capabilities.join(", ")
      : Object.entries(provider.capabilities || {}).filter(([, value]) => value).map(([key]) => key).join(", ");
    card.append(node("p", capabilities || provider.kind || "Capabilities unavailable", "knowledge-metadata"));
    if (provider.reason || provider.detail) card.append(node("p", provider.reason || provider.detail));
    if (provider.docs_url) card.append(sourceLink(provider.docs_url, "Provider documentation"));
    providers.append(card);
  }
  if (!providers.childNodes.length) empty(providers, "Connect the Knowledge service to inspect all five provider adapters and AI Search.");
}

export function renderSources(sources) {
  const target = element("knowledge-source-list");
  target.replaceChildren();
  for (const source of sources || []) {
    const card = node("article", undefined, "knowledge-card");
    card.append(node("h3", `${source.product} · ${source.version || "Version unspecified"}`),
      sourceLink(source.url),
      node("p", `${source.enabled ? "Enabled" : "Disabled"} · ${source.pinned ? "Pinned" : "Unpinned"} · ${source.provider} · every ${source.refresh_hours}h`),
      node("p", `Last source check: ${when(source.last_checked_at)}`, "knowledge-metadata"),
      node("p", source.current_artifact ? `Published artifact: ${source.current_artifact}` : "No published artifact; version coverage is not established.", "knowledge-metadata"));
    const actions = node("div", undefined, "knowledge-actions");
    actions.append(button("Refresh source", "refresh", source.id),
      button(source.enabled ? "Disable source" : "Enable source", source.enabled ? "disable" : "enable", source.id, source.revision),
      button(source.pinned ? "Unpin version" : "Pin version", source.pinned ? "unpin" : "pin", source.id, source.revision));
    const schedule = node("label", "Refresh interval (hours) ");
    const interval = node("input");
    interval.type = "number"; interval.min = "1"; interval.max = "720"; interval.step = "1";
    interval.value = source.refresh_hours; interval.required = true; interval.dataset.refreshHours = "true";
    schedule.append(interval);
    actions.append(schedule, button("Save interval", "interval", source.id, source.revision));
    card.append(actions);
    target.append(card);
  }
  if (!target.childNodes.length) empty(target, "No sources registered. Add a permitted public documentation URL above.");
}

export function renderJobs(jobs) {
  const target = element("knowledge-jobs");
  target.replaceChildren();
  for (const job of jobs || []) {
    const card = node("article", undefined, "knowledge-card");
    card.append(node("h3", job.status), node("p", `Source: ${job.source_id}`),
      node("p", job.reason || "No additional status detail."),
      node("p", `Updated: ${when(job.updated_at)}`, "knowledge-metadata"));
    if (job.artifact_id) card.append(node("p", `Artifact: ${job.artifact_id}`, "knowledge-metadata"));
    if (!["complete", "completed", "failed", "cancelled", "superseded"].includes(job.status)) {
      card.append(button("Cancel future work", "cancel", job.id));
    }
    target.append(card);
  }
  if (!target.childNodes.length) empty(target, "No indexing jobs have been created.");
}

export function renderUsage(usage) {
  const target = element("knowledge-usage");
  if (!usage?.length) { empty(target, "No usage receipts are available."); return; }
  const table = node("table");
  const head = node("thead"), labels = node("tr");
  for (const label of ["Provider", "Confirmed", "Pending", "Unknown", "Background", "Total / cap"]) {
    const cell = node("th", label); cell.scope = "col"; labels.append(cell);
  }
  head.append(labels);
  const body = node("tbody");
  for (const item of usage) {
    const row = node("tr");
    for (const value of [item.provider, item.confirmed, item.pending, item.unknown, item.background, `${item.total} / ${item.limit}`]) row.append(node("td", value ?? "Unknown"));
    body.append(row);
  }
  table.append(head, body);
  const shell = node("div", undefined, "knowledge-table-shell");
  shell.append(table); target.replaceChildren(shell);
}

function excerptCard(excerpt) {
  const card = node("article", undefined, "knowledge-card");
  card.append(node("h3", excerpt.title || "Source excerpt"), sourceLink(excerpt.url),
    node("blockquote", excerpt.text, "knowledge-excerpt"));
  const version = excerpt.version || { kind: "unknown" };
  card.append(node("p", `Target match: ${excerpt.target_match || "unverified"} · observed version: ${version.version || "Unknown"} · basis: ${version.kind}`, "knowledge-metadata"));
  if (version.proof_url) card.append(sourceLink(version.proof_url, "Version evidence"));
  if (excerpt.locator) card.append(node("p", `Artifact ${excerpt.artifact_id} · UTF-8 bytes ${excerpt.locator.start_byte}–${excerpt.locator.end_byte}`, "knowledge-metadata"));
  return card;
}

export function renderEvidence(result) {
  const target = element("knowledge-results");
  target.replaceChildren();
  target.append(node("p", `${result.path || "Unknown path"} · ${result.elapsed_ms ?? "Unknown"} ms · ${result.token_count ?? "Unknown"} tokens (${result.token_counting_method || "count unavailable"})`, "knowledge-metadata"));
  target.append(node("p", `Providers used: ${(result.providers_used || []).join(", ") || "None"}`, "knowledge-metadata"));
  for (const gap of result.gaps || []) target.append(node("p", `${gap.code}: ${gap.message}`, "knowledge-gap"));
  for (const excerpt of result.excerpts || []) target.append(excerptCard(excerpt));
  if (!result.excerpts?.length) target.append(node("p", "No qualifying excerpts were found for this request."));
  if (result.related_evidence?.length) {
    const related = node("details");
    related.append(node("summary", `Related evidence with unverified target compatibility (${result.related_evidence.length})`));
    for (const excerpt of result.related_evidence) related.append(excerptCard(excerpt));
    target.append(related);
  }
  if (result.freshness) {
    const detail = node("details");
    detail.append(node("summary", "Freshness and usage receipts"), node("pre", JSON.stringify({ freshness: result.freshness, usage: result.usage || [] }, null, 2)));
    target.append(detail);
  }
}
