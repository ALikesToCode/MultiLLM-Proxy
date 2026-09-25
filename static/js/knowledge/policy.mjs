import { element, node } from "./render.mjs";

const PROVIDERS = ["context7", "firecrawl", "exa", "mintlify", "deepwiki", "ai_search", "alexandria"];
const LABELS = { context7: "Context7", firecrawl: "Firecrawl", exa: "Exa", mintlify: "Mintlify Index", deepwiki: "DeepWiki", ai_search: "AI Search", alexandria: "Alexandria · Firecrawl credits" };

function input(label, name, value, checkbox = false) {
  const wrapper = node("label", undefined, checkbox ? "check-field" : "form-field");
  const field = node("input");
  field.name = name; field.type = checkbox ? "checkbox" : "number";
  if (checkbox) field.checked = Boolean(value);
  else {
    field.value = String(value ?? 0); field.min = name.endsWith("units_per_call") ? "1" : "0";
    field.max = "100000"; field.step = "1"; field.required = true;
  }
  wrapper.append(checkbox ? field : node("span", label), checkbox ? node("span", label) : field);
  return wrapper;
}

export function renderPolicy(policy) {
  const form = element("knowledge-policy-form");
  element("knowledge-policy-fields").disabled = !policy;
  if (!policy) return;
  form.dataset.revision = String(policy.revision);
  form.elements.namedItem("enabled").checked = policy.enabled;
  for (const name of ["cache_ttl_seconds", "retention_hours", "unreviewed_retention_hours"]) form.elements.namedItem(name).value = policy[name] ?? 24;
  form.elements.namedItem("allowed_hosts").value = (policy.allowed_hosts || []).join("\n");
  const cards = element("knowledge-provider-policy");
  cards.replaceChildren();
  for (const id of PROVIDERS) {
    const allocation = policy.providers[id] || {};
    const card = node("div", undefined, "card knowledge-provider-policy");
    card.append(node("h3", LABELS[id], "card__title"), input("Enable provider", `${id}.enabled`, allocation.enabled, true));
    if (id === "alexandria") card.append(node("p", "Free discovery works while disabled. Each retrieval reserves credits and records the actual charge; variable per-record totals can exceed the reservation.", "card__meta"));
    for (const [name, label] of [["limit", "Total units / rolling 24h"], ["background_limit", "Background cap"],
      ["interactive_reserve", "Reserve for interactive queries"], ["units_per_call", "Conservative units per operation"]]) {
      const field = input(id === "alexandria" && name === "limit" ? "Credits / rolling 24h" : label, `${id}.${name}`, allocation[name]);
      if (id === "alexandria" && name !== "limit") field.hidden = true;
      card.append(field);
    }
    card.append(input("Upstream billing hard stop confirmed", `${id}.hard_limit_confirmed`, allocation.hard_limit_confirmed, true),
      input("Retention of source content is permitted", `${id}.retention_allowed`, allocation.retention_allowed, true));
    cards.append(card);
  }
  element("knowledge-policy-status").textContent = `Policy revision ${policy.revision}. Changes apply only when saved.`;
}

export function policyPayload(values, revision) {
  const providers = {};
  for (const id of PROVIDERS) {
    const allocation = {};
    for (const name of ["enabled", "hard_limit_confirmed", "retention_allowed"]) allocation[name] = values.get(`${id}.${name}`) === "on";
    for (const name of ["limit", "background_limit", "interactive_reserve", "units_per_call"]) allocation[name] = Number(values.get(`${id}.${name}`));
    providers[id] = allocation;
  }
  return { expected_revision: Number(revision), enabled: values.get("enabled") === "on",
    cache_ttl_seconds: Number(values.get("cache_ttl_seconds")), retention_hours: Number(values.get("retention_hours")),
    unreviewed_retention_hours: Number(values.get("unreviewed_retention_hours")),
    allowed_hosts: String(values.get("allowed_hosts") || "").split(/\s+/).filter(Boolean), providers };
}
