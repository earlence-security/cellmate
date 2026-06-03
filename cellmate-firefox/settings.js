// MV2 wrappers
const sGet = (k) => new Promise(res => chrome.storage.local.get(k, res));
const sSet = (obj) => new Promise(res => chrome.storage.local.set(obj, res));
const sRemove = (k) => new Promise(res => chrome.storage.local.remove(k, res));

function flash(el, msg, { danger = false } = {}) {
  el.textContent = msg;
  el.classList.toggle("danger", danger);
  el.style.display = "block";
  setTimeout(() => { el.style.display = "none"; }, 2500);
}

document.addEventListener("DOMContentLoaded", async () => {
  // Back
  document.getElementById("back-btn").addEventListener("click", () => {
    window.location.href = "popup.html";
  });

  // Toggle: disallow_untrusted_domains (default ON)
  const box = document.getElementById("disallow");
  const { disallow_untrusted_domains } = await sGet("disallow_untrusted_domains");
  box.checked = (disallow_untrusted_domains === undefined) ? true : !!disallow_untrusted_domains;
  box.addEventListener("change", async () => {
    await sSet({ disallow_untrusted_domains: box.checked });
  });

  // API key controls
  const apiInput = document.getElementById("apiKeyInput");
  const setBtn = document.getElementById("setApiKeyBtn");
  const removeBtn = document.getElementById("removeApiKeyBtn");
  const statusEl = document.getElementById("apiStatus");

  // If a key exists, show a small status (don’t prefill the box)
  const existing = await sGet("api_key");
  if (existing.api_key) {
    flash(statusEl, "An API key is saved.");
  }

  // Set API key
  setBtn.addEventListener("click", async () => {
    const val = apiInput.value.trim();
    if (!val) {
      flash(statusEl, "Please enter an API key.", { danger: true });
      return;
    }
    await sSet({ api_key: val });
    apiInput.value = "";
    flash(statusEl, "API key saved.");
  });

  removeBtn.addEventListener("click", async () => {
    await sRemove("api_key");
    flash(statusEl, "Saved API key removed.");
  });
});
