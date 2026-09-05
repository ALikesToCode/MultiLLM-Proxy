import { action, api, download, element, status } from "./api.mjs";

export function initProfiles() {
  const form = element("profile-form");
  let profiles = [], preview = null;
  const read = () => Object.fromEntries(new FormData(form));
  const refresh = async () => {
    profiles = (await api("profiles")).profiles;
    const select = element("saved-profile");
    select.replaceChildren(new Option("New profile", ""));
    for (const profile of profiles) select.add(new Option(profile.name, profile.id));
  };
  const invalidate = () => { preview = null; element("export-profile").disabled = true; };
  form.addEventListener("input", invalidate);
  element("saved-profile").addEventListener("change", () => {
    const selected = profiles.find((profile) => profile.id === element("saved-profile").value);
    if (selected) for (const field of form.elements) if (Object.hasOwn(selected, field.name)) field.value = selected[field.name];
    invalidate();
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    try { await api("profiles", read()); await refresh(); status("Profile saved. Existing profiles were preserved."); }
    catch (error) { status(error.message); }
    finally { submit.disabled = false; }
  });
  action("preview-profile", async () => {
    const input = read();
    const result = await api("profiles/preview", input);
    if (JSON.stringify(input) !== JSON.stringify(read())) throw new Error("Profile changed during validation. Preview the current settings again.");
    preview = result;
    element("profile-preview").textContent = JSON.stringify(preview, null, 2);
    element("export-profile").disabled = false;
    status("Profile validated against configured routes. No generation was started.");
  });
  action("export-profile", () => {
    if (!preview) throw new Error("Preview the current profile before export.");
    download("connection-profile.json", { ...preview.connection, receipt: preview.receipt });
  });
  return refresh;
}
