import { api } from "./api.mjs";
import { element, node } from "./render.mjs";

export function costText(result) {
  const cost = result.cost;
  if (cost?.state === "confirmed" && Number.isSafeInteger(cost.credits)) {
    return `Cost: ${cost.credits} Firecrawl credits.${result.reservation_exceeded ? " The charge exceeded the reservation." : ""}${result.call_cost ? " Reading this receipt added no charge." : ""}`;
  }
  return `Cost: ${cost?.state === "pending" ? "pending" : "unknown"}. The reservation remains held; check this receipt before making another request.`;
}

export function renderTools(tools) {
  const list = element("alexandria-tools");
  list.replaceChildren();
  for (const tool of tools) {
    const card = node("article", undefined, "knowledge-card");
    card.append(node("h3", tool.name), node("code", `${tool.provider}/${tool.capability}`),
      node("p", tool.whenToUse || tool.description), node("p", `${tool.creditsCost} credits per ${tool.perRecord ? "record" : "call"}`));
    const button = node("button", "Inspect contract · free", "button");
    button.type = "button"; button.dataset.quoteId = tool.quote_id;
    card.append(button); list.append(card);
  }
  if (!tools.length) list.append(node("p", "No capabilities matched. Try a more specific data request."));
}

export function executionPayload(form, tool) {
  let options;
  try { options = JSON.parse(form.elements.namedItem("options").value); }
  catch { throw new Error("Capability options must be valid JSON."); }
  if (!options || typeof options !== "object" || Array.isArray(options)) throw new Error("Capability options must be a JSON object.");
  return { quote_id: tool.quote_id, request_id: form.elements.namedItem("request_id").value, options,
    reserve_credits: Number(form.elements.namedItem("reserve_credits").value),
    accept_variable_cost: form.elements.namedItem("accept_variable_cost").checked };
}

export function initializeAlexandria(formAction, loadStatus) {
  let tools = [], selected = null, submitting = false;
  const form = element("alexandria-execute-form");
  const showResult = result => {
    element("alexandria-cost").textContent = costText(result);
    element("alexandria-result").hidden = false;
    element("alexandria-result").textContent = JSON.stringify(result, null, 2);
    if (result.error) element("alexandria-status").textContent = result.error.message;
  };

  formAction("alexandria-search-form", "alexandria-status", async searchForm => {
    selected = null;
    element("alexandria-selected").hidden = true;
    renderTools([]);
    const result = await api("alexandria/search", { method: "POST", body: { query: new FormData(searchForm).get("query"), limit: 5 } });
    showResult(result);
    tools = result.tools || [];
    renderTools(tools);
    if (!result.error) element("alexandria-status").textContent = `Found ${tools.length} capabilities. Inspect a contract before retrieving data.`;
  });

  element("alexandria-tools").addEventListener("click", async event => {
    const button = event.target.closest("button[data-quote-id]");
    if (!button || submitting) return;
    const tool = tools.find(item => item.quote_id === button.dataset.quoteId);
    if (!tool) return;
    submitting = true; button.disabled = true;
    selected = null;
    element("alexandria-selected").hidden = true;
    try {
      const result = await api("alexandria/inspect", { method: "POST", body: { quote_id: tool.quote_id } });
      showResult(result);
      if (result.error) return;
      selected = tool;
      element("alexandria-selection").textContent = `${tool.provider}/${tool.capability}`;
      element("alexandria-price").textContent = `${tool.creditsCost} credits per ${tool.perRecord ? "record (variable total)" : "call"}. Discovery expires at ${new Date(tool.expires_at).toLocaleTimeString()}.`;
      element("alexandria-contract").textContent = JSON.stringify({ discovered: tool, inspected: result.details }, null, 2);
      form.elements.namedItem("options").value = "{}";
      form.elements.namedItem("reserve_credits").value = tool.creditsCost;
      form.elements.namedItem("request_id").value = crypto.randomUUID();
      form.elements.namedItem("accept_variable_cost").checked = false;
      form.elements.namedItem("accept_variable_cost").required = tool.perRecord;
      element("alexandria-variable").hidden = !tool.perRecord;
      element("alexandria-selected").hidden = false;
      element("alexandria-execute").disabled = false;
      element("alexandria-receipt").disabled = true;
      element("alexandria-status").textContent = "Review the options and price. Retrieval requires the Alexandria allowance to be enabled.";
    } catch (error) { element("alexandria-status").textContent = error.message; }
    finally { submitting = false; button.disabled = false; }
  });

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (!selected || submitting || element("alexandria-execute").disabled) return;
    let payload;
    try { payload = executionPayload(form, selected); }
    catch (error) { element("alexandria-status").textContent = error.message; return; }
    submitting = true;
    element("alexandria-execute").disabled = true;
    element("alexandria-cost").textContent = `Request ${payload.request_id}: cost pending.`;
    try {
      showResult(await api("alexandria/execute", { method: "POST", body: payload }));
      await loadStatus();
    } catch (error) {
      element("alexandria-status").textContent = error.message;
      element("alexandria-cost").textContent = "No execution receipt received. Check this request's receipt before starting another retrieval.";
    } finally { submitting = false; element("alexandria-receipt").disabled = false; }
  });

  element("alexandria-receipt").addEventListener("click", async () => {
    try { showResult(await api("alexandria/receipt", { method: "POST", body: { request_id: form.elements.namedItem("request_id").value } })); }
    catch (error) { element("alexandria-status").textContent = error.message; }
  });
}
