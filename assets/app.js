function setCopied(button) {
  const prev = button.textContent;
  button.textContent = "Skopiowano";
  button.disabled = true;
  window.setTimeout(() => {
    button.textContent = prev;
    button.disabled = false;
  }, 1200);
}

async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const el = document.createElement("textarea");
  el.value = text;
  el.setAttribute("readonly", "true");
  el.style.position = "fixed";
  el.style.top = "-1000px";
  document.body.appendChild(el);
  el.select();
  document.execCommand("copy");
  document.body.removeChild(el);
}

document.addEventListener("click", async (e) => {
  const target = e.target instanceof HTMLElement ? e.target : null;
  if (!target) return;
  const confirmText = target.getAttribute("data-confirm");
  if (confirmText) {
    const ok = window.confirm(confirmText);
    if (!ok) {
      e.preventDefault();
      e.stopPropagation();
      return;
    }
  }
  const copyValue = target.getAttribute("data-copy");
  if (!copyValue) return;
  try {
    await copyText(copyValue);
    setCopied(target);
  } catch {
    target.textContent = "Błąd";
  }
});
