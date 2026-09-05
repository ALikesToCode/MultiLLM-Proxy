import { action, api, element, status } from "./api.mjs";
import { initProfiles } from "./profiles.mjs";
import { initLab } from "./lab.mjs";
import { initSessions } from "./sessions.mjs";

const refreshProfiles = initProfiles();
initLab();
initSessions();
action("check-deployment", async () => {
  element("deployment-result").textContent = "Checking Worker, Container and preflight responses…";
  element("deployment-result").textContent = JSON.stringify(await api("deployment?probe=true"), null, 2);
});

async function loadCatalog() {
  const catalog = await api("catalog");
  const models = new Set();
  for (const route of catalog.models || catalog.data || []) {
    if (!route.provider || !route.model) continue;
    const billing = route.billing_mode === "subscription" ? "subscription-only" : "configured";
    const option = new Option(`${route.provider} / ${route.model} · ${billing}`, JSON.stringify({ provider: route.provider, model: route.model, billing }));
    element("lab-candidates").add(option); models.add(route.model);
  }
  for (const model of models) element("model-catalog").append(new Option(model, model));
  element("lab-status").textContent = "Ready. Speed is measured here; catalog TPS is not assumed.";
}
const results = await Promise.allSettled([refreshProfiles(), loadCatalog()]);
const failed = results.filter((result) => result.status === "rejected");
status(failed.length ? failed.map((result) => result.reason.message).join(" · ") : "Workbench ready. No generation starts until you confirm it.");
