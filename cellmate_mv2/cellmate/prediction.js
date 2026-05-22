// prediction.js
import { requestDomainSuggestions } from "./llmClient.js";

// --- MV2 helpers ---
const sGet = (k) => new Promise(res => chrome.storage.local.get(k, res));
const sSet = (o) => new Promise(res => chrome.storage.local.set(o, res));

function flash(el, msg, { error = false } = {}) {
  el.textContent = msg;
  el.classList.toggle("error", !!error);
  el.style.display = "block";
  setTimeout(() => { el.style.display = "none"; }, 2500);
}

async function loadResourcesIndex() {
  const url = chrome.runtime.getURL("resources/index.json");
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to load ${url} (${resp.status})`);
  return resp.json(); // ["gitlab.com", ...]
}

function tag(text) {
  const el = document.createElement("span");
  el.className = "tag";
  el.textContent = text;
  return el;
}

function chip(domain, { clickable, onClick }) {
  const el = document.createElement("span");
  el.className = "chip" + (clickable ? "" : " disabled");
  el.textContent = domain;
  if (clickable) el.addEventListener("click", () => onClick?.(domain));
  else el.title = "No resources available for this domain";
  return el;
}

function renderRestrictionState(targetEl, { active, domains }) {
  targetEl.innerHTML = "";
  if (!active) {
    targetEl.textContent = "No restriction is active.";
    return;
  }
  if (!domains || domains.length === 0) {
    targetEl.textContent = "Restriction is active but the allowlist is empty.";
    return;
  }
  targetEl.append("Restriction active: ");
  domains.forEach(d => targetEl.appendChild(tag(d)));
}

document.addEventListener("DOMContentLoaded", async () => {
  // Navigation
  document.getElementById("back-btn").addEventListener("click", () => {
    window.location.href = "popup.html";
  });

  // Elements
  const taskInput = document.getElementById("taskInput");
  const suggestBtn = document.getElementById("suggestDomainsBtn");
  const statusEl = document.getElementById("taskStatus");
  const apiKeyHint = document.getElementById("apiKeyHint");

  const results = document.getElementById("results");
  const chips = document.getElementById("chips");
  const domainSelect = document.getElementById("domainSelect");
  const predictBtn = document.getElementById("predictPolicyBtn");
  const predictedSection = document.getElementById("predictedSection");

  const applyRestrictionBtn = document.getElementById("applyRestrictionBtn");
  const clearRestrictionBtn = document.getElementById("clearRestrictionBtn");
  const restrictionState = document.getElementById("restrictionState");

  // Page-level state: the last list predicted for the CURRENT task
  let lastPredicted = null;

  // Load resource-backed domains
  let resourceDomains = [];
  try {
    resourceDomains = await loadResourcesIndex();
  } catch (e) {
    console.error("[prediction] Failed to load resources/index.json", e);
  }
  domainSelect.innerHTML = resourceDomains.map(d => `<option value="${d}">${d}</option>`).join("");

  // API key hint
  const { api_key } = await sGet("api_key");
  if (!api_key) apiKeyHint.style.display = "block";

  // Initial restriction state (always visible panel)
  const initStore = await sGet(["predicted_domain_allowlist_active", "predicted_domain_allowlist"]);
  renderRestrictionState(restrictionState, {
    active: !!initStore.predicted_domain_allowlist_active,
    domains: initStore.predicted_domain_allowlist || []
  });

  // Disable "Restrict" until we have predictions for the current task
  applyRestrictionBtn.disabled = true;
  applyRestrictionBtn.title = "Get domain suggestions first";

  // Suggest domains (LLM)
  suggestBtn.addEventListener("click", async () => {
    const task = (taskInput.value || "").trim();
    if (!task) {
      flash(statusEl, "Please enter a brief description of your task.", { error: true });
      return;
    }
    if (!api_key) {
      flash(statusEl, "No API key set. Go to Settings to add a key.", { error: true });
      return;
    }

    suggestBtn.disabled = true;

    try {
      // Get model suggestions
      const predicted = await requestDomainSuggestions({
        apiKey: api_key,
        userTask: task,
        maxDomains: 12
      });

      // Keep this exact list for restriction button
      lastPredicted = predicted;

      // Enable/disable Restrict button based on result
      const hasList = Array.isArray(predicted) && predicted.length > 0;
      applyRestrictionBtn.disabled = !hasList;
      applyRestrictionBtn.title = hasList ? "" : "No domains were suggested";
      predictedSection.style.display = hasList ? "block" : "none";

      // Render chips for ALL predicted domains; only resource-backed ones are clickable
      const clickableSet = new Set(resourceDomains);
      chips.innerHTML = "";
      if (hasList) {
        predicted.forEach(d => {
          const clickable = clickableSet.has(d);
          chips.appendChild(chip(d, {
            clickable,
            onClick: (domain) => {
              const q = new URLSearchParams({ domain, predict: "1", task }).toString();
              window.location.href = `edit.html?${q}`;
            }
          }));
        });
      } else {
        chips.innerHTML = `<div class="muted">No domains suggested. You can still pick a domain below.</div>`;
      }

      // Show results area
      results.style.display = "block";

      // Preselect dropdown: first predicted that has resources, else first resource
      const firstClickable = (predicted || []).find(d => clickableSet.has(d));
      if (firstClickable) domainSelect.value = firstClickable;
      else if (resourceDomains.length) domainSelect.value = resourceDomains[0];

      // Predict policy button (navigates to edit with predict=1)
      predictBtn.onclick = () => {
        const chosen = domainSelect.value;
        if (!chosen) {
          flash(statusEl, "Please pick a domain.", { error: true });
          return;
        }
        const q = new URLSearchParams({ domain: chosen, predict: "1", task }).toString();
        window.location.href = `edit.html?${q}`;
      };

      // Refresh restriction panel view from storage (in case user had one active)
      const cur = await sGet(["predicted_domain_allowlist_active", "predicted_domain_allowlist"]);
      renderRestrictionState(restrictionState, {
        active: !!cur.predicted_domain_allowlist_active,
        domains: cur.predicted_domain_allowlist || []
      });

    } catch (err) {
      console.error("[prediction] Domain suggestion failed:", err);
      flash(statusEl, String(err.message || err), { error: true });
    } finally {
      suggestBtn.disabled = false;
    }
  });

  // Apply restriction using the latest predicted list (no re-predict here)
  applyRestrictionBtn.addEventListener("click", async () => {
    if (!lastPredicted || lastPredicted.length === 0) {
      // Defensive: should be disabled anyway
      return;
    }
    await sSet({
      predicted_domain_allowlist_active: true,
      predicted_domain_allowlist: lastPredicted,
      predicted_domain_allowlist_ts: Date.now()
    });
    renderRestrictionState(restrictionState, { active: true, domains: lastPredicted });
    flash(statusEl, "Restriction applied from latest predicted domains.");
  });

  // Clear restriction
  clearRestrictionBtn.addEventListener("click", async () => {
    await sSet({
      predicted_domain_allowlist_active: false,
      predicted_domain_allowlist: [],
      predicted_domain_allowlist_ts: Date.now()
    });
    renderRestrictionState(restrictionState, { active: false, domains: [] });
    flash(statusEl, "Restriction cleared.");
  });
});
