const status = document.getElementById("agent-copy-status");

for (const button of document.querySelectorAll("[data-copy-target]")) {
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.copyTarget);
    if (!target) return;
    const text = target.value ?? target.textContent;
    try {
      await navigator.clipboard.writeText(text);
      status.textContent = "Copied. Paste into your client.";
    } catch {
      if (typeof target.select === "function") {
        target.focus();
        target.select();
      } else {
        const range = document.createRange();
        range.selectNodeContents(target);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
      }
      status.textContent = "Copy is unavailable. The text is selected; copy it manually.";
    }
  });
}
