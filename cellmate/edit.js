// import policy engine classes
import { Policy, Sitemap, Action } from "./policyEngine.js";
import { requestPolicySuggestions } from "./llmClient.js";

const qs = sel => document.querySelector(sel);

// --- Small MV2 wrappers so we can use await cleanly ---
const tabsQuery = (q) => new Promise((res, rej) =>
  chrome.tabs.query(q, t => chrome.runtime.lastError ? rej(chrome.runtime.lastError) : res(t))
);
const storageGet = (keys) => new Promise((res, rej) =>
  chrome.storage.local.get(keys, r => chrome.runtime.lastError ? rej(chrome.runtime.lastError) : res(r))
);
const storageSet = (obj) => new Promise((res, rej) =>
  chrome.storage.local.set(obj, () => chrome.runtime.lastError ? rej(chrome.runtime.lastError) : res())
);


// --- Helpers ---
async function getCurrentDomain() {
  const [tab] = await tabsQuery({ active: true, currentWindow: true });
  return new URL(tab.url).hostname;
}

async function fetchJson(extPath) {
  const url = chrome.runtime.getURL(extPath);
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Fetch failed ${resp.status}: ${extPath}`);
  return resp.json();
}

/**
 * Try to load template + rules + sitemap for a domain.
 * Returns { template, rulesIndex, rulesMap, sitemap }.
 * If any file is missing => throws, so caller can display "unavailable".
 */
async function loadDomainResources(domain) {
  // Required:
  // resources/<domain>/policy.json
  // resources/<domain>/sitemap.json
  // resources/<domain>/rules/index.json  -> ["read_api.json", ...]
  const base = `resources/${domain}`;
  const [template, sitemap, rulesIndex] = await Promise.all([
    fetchJson(`${base}/policy.json`),
    fetchJson(`${base}/sitemap.json`),
    fetchJson(`${base}/rules/index.json`)
  ]);

  // Load all rule JSONs listed in index.json
  const entries = await Promise.all(
    rulesIndex.map(async fname => {
      const obj = await fetchJson(`${base}/rules/${fname}`);
      const slug = fname.replace(/\.json$/i, "");
      return [slug, obj];
    })
  );
  const rulesMap = Object.fromEntries(entries); // { slug -> ruleObject }

  return { template, rulesIndex, rulesMap, sitemap };
}

/**
 * Try to deduce which rule slugs are already in the current policy.
 * Strategy:
 *   - Prefer exact deep equality against available rule objects.
 *   - If we previously stored selected_rule_slugs, use it as a fallback.
 */
function inferSelectedSlugs(currentPolicy, rulesMap, fallbackSlugs = []) {
  if (!currentPolicy || !Array.isArray(currentPolicy.rules)) return fallbackSlugs;

  const byString = new Map(
    Object.entries(rulesMap).map(([slug, rule]) => [JSON.stringify(rule), slug])
  );

  const slugs = [];
  for (const rule of currentPolicy.rules) {
    const key = JSON.stringify(rule);
    if (byString.has(key)) slugs.push(byString.get(key));
  }
  // Merge in any fallback slugs not already present
  for (const s of fallbackSlugs) if (!slugs.includes(s)) slugs.push(s);
  return slugs;
}

/**
 * Render the rules list with toggles.
 */
function renderRulesList(domain, rulesMap, preselectedSlugs = []) {
  const container = qs("#rules");
  container.innerHTML = "";

  const slugs = Object.keys(rulesMap).sort();
  if (slugs.length === 0) {
    container.innerHTML = `<div class="muted">No rules available for <b>${domain}</b>.</div>`;
    return;
  }

  for (const slug of slugs) {
    const id = `rule_${slug}`;
    const row = document.createElement("div");
    row.className = "rule-row";
    row.innerHTML = `
      <div class="rule-name">${rulesMap[slug]["description"]}</div>
      <label class="toggle">
        <input type="checkbox" id="${id}" ${preselectedSlugs.includes(slug) ? "checked" : ""}>
        <span class="slider"></span>
      </label>
    `;
    container.appendChild(row);
  }
}

/**
 * Gather selected rule slugs from the UI.
 */
function getSelectedSlugs() {
  const boxes = Array.from(document.querySelectorAll('.rule-row input[type="checkbox"]'));
  return boxes.filter(cb => cb.checked).map(cb => cb.id.replace(/^rule_/, ""));
}

/**
 * Compile the final policy by inserting selected rules into the template.
 */
function compilePolicy(template, rulesMap, selectedSlugs) {
  const policy = JSON.parse(JSON.stringify(template)); // deep clone
  policy.rules = selectedSlugs.map(slug => rulesMap[slug]);
  return policy;
}

/**
 * Produce target_requests by evaluating the policy across all sitemap endpoints.
 */
function computeTargetRequests(policyObj, sitemapObj) {
  const policy = Policy.fromDict(policyObj);
  const sitemap = new Sitemap(sitemapObj);

  const targets = [];
  for (const entry of sitemap.entries) {
    // NOTE: if your sitemap uses {param} placeholders, consider the “templateToExampleUrl”
    // trick or the “self-match” tweak discussed earlier to ensure tags resolve.
    const action = Action.fromEndpoint({
      url: entry.urlTemplate,
      method: entry.method,
      sitemap
    });

    const decision = policy.evaluate(action);
    console.log("[DBG] entry:", entry.method, entry.urlTemplate,
                "tags:", action.tags, "decision:", decision);

    // NEW RULE: include any endpoint that is NOT explicitly "allow"
    if (decision !== "allow") {
      if (Object.keys(entry.body).length === 0) {
        targets.push({ url: entry.urlTemplate, method: entry.method, decision }); // decision ∈ {"deny","allow_public"}
      }
      else {
        targets.push({ url: entry.urlTemplate, method: entry.method, decision, body: entry.body }); // decision ∈ {"deny","allow_public"}
      }
    }
  }
  return targets;
}

/**
 * Show an error or info message in #status.
 */
function setStatus(html) {
  qs("#status").innerHTML = html;
}

/**
 * Render the rules list, with suggested rules on top separated by a line.
 */
function renderRulesWithSuggestions({ domain, rulesMap, suggestedTrueSlugs, keepSelectedSlugs }) {
  const container = document.getElementById("rules");
  container.innerHTML = "";

  // Build section DOM helper
  function addSeparator(label) {
    const sep = document.createElement("div");
    sep.className = "separator";
    sep.innerHTML = `<span>${label}</span>`;
    container.appendChild(sep);
  }

  // Suggested TRUE on top
  if (suggestedTrueSlugs.length > 0) {
    addSeparator("LLM Suggested Rules");
    for (const slug of suggestedTrueSlugs) {
      const id = `rule_${slug}`;
      const row = document.createElement("div");
      row.className = "rule-row";
      row.innerHTML = `
        <div class="rule-name">${rulesMap[slug].description}</div>
        <label class="toggle">
          <input type="checkbox" id="${id}" ${keepSelectedSlugs.includes(slug) ? "checked" : ""}>
          <span class="slider"></span>
        </label>
      `;
      container.appendChild(row);
    }
  }

  // Remaining (everything else)
  const allSlugs = Object.keys(rulesMap).sort();
  const remaining = allSlugs.filter(s => !suggestedTrueSlugs.includes(s));

  if (remaining.length > 0) {
    addSeparator("Remaining Rules");
    for (const slug of remaining) {
      const id = `rule_${slug}`;
      const row = document.createElement("div");
      row.className = "rule-row";
      row.innerHTML = `
        <div class="rule-name">${rulesMap[slug].description}</div>
        <label class="toggle">
          <input type="checkbox" id="${id}" ${keepSelectedSlugs.includes(slug) ? "checked" : ""}>
          <span class="slider"></span>
        </label>
      `;
      container.appendChild(row);
    }
  }
}


(async function main() {
  const backBtn = document.getElementById("back-btn");
  const submitBtn = document.getElementById("submit-btn");

  const params = new URLSearchParams(location.search);
  const forcedDomain = params.get("domain");
  const predictFlag = params.get("predict") === "1";
  const taskFromURL = params.get("task") ? decodeURIComponent(params.get("task")) : null;

  backBtn.addEventListener("click", () => (window.location.href = "popup.html"));

  // Pick domain: URL param > current tab
  const domain = forcedDomain || await getCurrentDomain();

  // Load any existing entry for this domain
  const stored = await new Promise((res, rej) =>
    chrome.storage.local.get(domain, r => chrome.runtime.lastError ? rej(chrome.runtime.lastError) : res(r)));
  const existingEntry = stored[domain] || null;
  const existingPolicy = existingEntry?.policy || null;
  const storedSlugs = existingEntry?.selected_rule_slugs || [];

  // Attempt to load resources for the (possibly forced) domain
  let resources;
  try {
    resources = await (async () => {
      const base = `resources/${domain}`;
      const [template, sitemap, rulesIndex] = await Promise.all([
        fetchJson(`${base}/policy.json`),
        fetchJson(`${base}/sitemap.json`),
        fetchJson(`${base}/rules/index.json`)
      ]);
      const entries = await Promise.all(
        rulesIndex.map(async fname => {
          const obj = await fetchJson(`${base}/rules/${fname}`);
          const slug = fname.replace(/\.json$/i, "");
          return [slug, obj];
        })
      );
      return { template, rulesIndex, rulesMap: Object.fromEntries(entries), sitemap };
    })();
  } catch (e) {
    setStatus(`Policy setup is unavailable for <b>${domain}</b> as resources for this domain are not found.`);
    submitBtn.disabled = true;
    return;
  }

  const { template, rulesMap, sitemap } = resources;

  // If we're updating, preselect based on current policy; otherwise empty selection
  const preselected = inferSelectedSlugs(existingPolicy, rulesMap, storedSlugs);
  if (existingPolicy) {
    setStatus(`Updating policy for <b>${domain}</b>. Toggle rules below and press Submit.`);
  } else {
    setStatus(`Please select rules from below to add to your policy for <b>${domain}</b>.`);
  }

  // Initial render (plain list)
  renderRulesList(domain, rulesMap, preselected);
  submitBtn.disabled = false;

  // If predict=1 and task provided, auto-run policy suggestions and re-render grouped view
  if (predictFlag && taskFromURL) {
    try {
      const { api_key } = await new Promise(res => chrome.storage.local.get("api_key", res));
      if (api_key) {
        const { suggestedRules } = await requestPolicySuggestions({
          apiKey: api_key,
          userTask: taskFromURL,
          rulesMap,
          domain
        });

        const suggestedTrue = Object.entries(suggestedRules)
          .filter(([, v]) => v === true)
          .map(([slug]) => slug);

        const keepSelected = getSelectedSlugs(); // preserve prior checks
        renderRulesWithSuggestions({
          domain,
          rulesMap,
          suggestedTrueSlugs: suggestedTrue,
          keepSelectedSlugs: keepSelected
        });
      } else {
        console.warn("[edit] No API key found; skipping suggestion.");
      }
    } catch (err) {
      console.error("[edit] Auto-suggestion failed:", err);
    }
  }

  // Submit button logic
  submitBtn.addEventListener("click", async () => {
    submitBtn.disabled = true; // gray out to prevent double-submit

    try {
      const selected = getSelectedSlugs();
      const compiledPolicy = compilePolicy(template, rulesMap, selected);
      const targetRequests = computeTargetRequests(compiledPolicy, sitemap);

      const payload = {
        policy: compiledPolicy,
        selected_rule_slugs: selected,  // helpful for future edit preselects
        target_requests: targetRequests
      };

      await storageSet({ [domain]: payload });

      // Redirect back to popup with a small success flag & domain for banner
      const q = new URLSearchParams({ updated: "1", domain }).toString();
      window.location.href = `popup.html?${q}`;
    } catch (err) {
      console.error(err);
      setStatus(`<span style="color:#b91c1c">Failed to update policy: ${String(err.message || err)}</span>`);
      submitBtn.disabled = false; // re-enable to allow retry
    }
  });
})();
