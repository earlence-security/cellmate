// prediction.js
import { requestDomainSuggestions } from "./llmClient.js";

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
  return resp.json();
}

function chip(domain, { clickable, onClick }) {
  const el = document.createElement("span");
  el.className = "chip" + (clickable ? "" : " disabled");
  el.textContent = domain;
  if (clickable) el.addEventListener("click", () => onClick?.(domain));
  else el.title = "No resources available for this domain";
  return el;
}

document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("back-btn").addEventListener("click", () => window.close());

  // --- Elements ---
  const apiKeyCard    = document.getElementById("apiKeyCard");
  const apiKeyInput   = document.getElementById("apiKeyInput");
  const saveKeyBtn    = document.getElementById("saveKeyBtn");
  const keyStatus     = document.getElementById("keyStatus");
  const keySavedLabel = document.getElementById("keySavedLabel");
  const changeKeyBtn  = document.getElementById("changeKeyBtn");
  const taskInput     = document.getElementById("taskInput");
  const suggestBtn    = document.getElementById("suggestDomainsBtn");
  const taskStatus    = document.getElementById("taskStatus");
  const results       = document.getElementById("results");
  const chips         = document.getElementById("chips");
  const domainSelect  = document.getElementById("domainSelect");
  const predictBtn    = document.getElementById("predictPolicyBtn");
  const predictedSection = document.getElementById("predictedSection");

  // --- Load resource-backed domains ---
  let resourceDomains = [];
  try {
    resourceDomains = await loadResourcesIndex();
  } catch (e) {
    console.error("[prediction] Failed to load resources/index.json", e);
  }
  domainSelect.innerHTML = resourceDomains.map(d => `<option value="${d}">${d}</option>`).join("");

  // --- API key state ---
  let { api_key } = await sGet("api_key");

  function applyKeyState() {
    if (api_key) {
      apiKeyCard.style.display = "none";
      keySavedLabel.style.display = "inline";
      changeKeyBtn.style.display = "inline-block";
    } else {
      apiKeyCard.style.display = "flex";
      keySavedLabel.style.display = "none";
      changeKeyBtn.style.display = "none";
    }
  }
  applyKeyState();

  // Save key
  saveKeyBtn.addEventListener("click", async () => {
    const val = (apiKeyInput.value || "").trim();
    if (!val) { flash(keyStatus, "Please enter a key.", { error: true }); return; }
    await sSet({ api_key: val });
    api_key = val;
    apiKeyInput.value = "";
    applyKeyState();
    flash(taskStatus, "API key saved.");
  });

  // Change key (show card again)
  changeKeyBtn.addEventListener("click", () => {
    apiKeyCard.style.display = "flex";
    keySavedLabel.style.display = "none";
    changeKeyBtn.style.display = "none";
    apiKeyInput.focus();
  });

  // Allow Enter in the key input to save
  apiKeyInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") saveKeyBtn.click();
  });

  // --- Domain suggestion ---
  suggestBtn.addEventListener("click", async () => {
    const task = (taskInput.value || "").trim();
    if (!task) {
      flash(taskStatus, "Please describe your task first.", { error: true });
      return;
    }
    if (!api_key) {
      apiKeyCard.style.display = "flex";
      flash(taskStatus, "Enter your Anthropic API key above first.", { error: true });
      return;
    }

    suggestBtn.disabled = true;
    suggestBtn.textContent = "Thinking…";

    try {
      const predicted = await requestDomainSuggestions({
        apiKey: api_key,
        userTask: task,
        maxDomains: 12
      });

      const hasList = Array.isArray(predicted) && predicted.length > 0;
      predictedSection.style.display = hasList ? "block" : "none";

      const clickableSet = new Set(resourceDomains);
      const clickableDomains = (predicted || []).filter(d => clickableSet.has(d));
      const domainsParam = clickableDomains.join(",");

      chips.innerHTML = "";
      if (hasList) {
        predicted.forEach(d => {
          const clickable = clickableSet.has(d);
          chips.appendChild(chip(d, {
            clickable,
            onClick: (domain) => {
              const q = new URLSearchParams({ domain, predict: "1", task, ...(domainsParam && { domains: domainsParam }) }).toString();
              window.location.href = `edit.html?${q}`;
            }
          }));
        });
      } else {
        chips.innerHTML = `<div class="muted">No domains suggested. Pick one below to configure its policy.</div>`;
      }

      results.style.display = "block";

      const firstClickable = (predicted || []).find(d => clickableSet.has(d));
      if (firstClickable) domainSelect.value = firstClickable;
      else if (resourceDomains.length) domainSelect.value = resourceDomains[0];

      predictBtn.onclick = () => {
        const chosen = domainSelect.value;
        if (!chosen) { flash(taskStatus, "Please pick a domain.", { error: true }); return; }
        const q = new URLSearchParams({ domain: chosen, predict: "1", task, ...(domainsParam && { domains: domainsParam }) }).toString();
        window.location.href = `edit.html?${q}`;
      };

    } catch (err) {
      console.error("[prediction] Domain suggestion failed:", err);
      flash(taskStatus, String(err.message || err), { error: true });
    } finally {
      suggestBtn.disabled = false;
      suggestBtn.textContent = "Get domain suggestions";
    }
  });
});
