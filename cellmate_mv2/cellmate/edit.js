const qs = sel => document.querySelector(sel);

// --- Small MV2 wrappers so we can use await cleanly ---
const tabsQuery = (q) => new Promise((res, rej) =>
  chrome.tabs.query(q, t => chrome.runtime.lastError ? rej(chrome.runtime.lastError) : res(t))
);
const storageSet = (obj) => new Promise((res, rej) =>
  chrome.storage.local.set(obj, () => chrome.runtime.lastError ? rej(chrome.runtime.lastError) : res())
);


// --- Helpers ---
// Maps webarena port → bundled resource domain. IP can change between runs.
const WEBARENA_PORT_MAP = { "8023": "gitlab-webarena", "9999": "reddit-webarena" };

function getResourceDomain(origin) {
  try {
    const port = new URL(origin).port;
    return WEBARENA_PORT_MAP[port] || origin;
  } catch {
    return origin;
  }
}

async function getCurrentDomain() {
  const [tab] = await tabsQuery({ active: true, currentWindow: true });
  if (!tab?.url) throw new Error("No active tab URL");
  return new URL(tab.url).origin;
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

function getRuleParameters(rule) {
  return rule?.condition?.parameters && typeof rule.condition.parameters === "object"
    ? rule.condition.parameters
    : {};
}

function hasRuleArguments(rule) {
  return Object.keys(getRuleParameters(rule)).length > 0 || isStatefulRule(rule);
}

function isStatefulRule(rule) {
  return rule?.stateful === true || (typeof rule?.stateful === "number" && rule.stateful > 0);
}

function getDefaultStatefulCount(rule) {
  return typeof rule?.stateful === "number" && Number.isFinite(rule.stateful)
    ? Math.max(0, Math.floor(rule.stateful))
    : 1;
}

function getLiteralOptions(type) {
  const match = String(type || "").match(/^List\[Literal\[(.*)\]\]$/);
  if (!match) return [];

  const options = [];
  const re = /"((?:\\.|[^"\\])*)"/g;
  let cur;
  while ((cur = re.exec(match[1])) !== null) {
    options.push(cur[1].replace(/\\"/g, "\"").replace(/\\\\/g, "\\"));
  }
  return options;
}

function normalizeListDefault(value, multi) {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) return value.map(String);
  return multi ? [String(value)] : [String(value)];
}

function createNumericInput({ slug, paramName, defaultValue, required, allowFloat = false, initialValue = null }) {
  const input = document.createElement("input");
  input.type = "text";
  input.inputMode = allowFloat ? "decimal" : "numeric";
  input.className = "rule-param num-param";
  input.dataset.ruleSlug = slug;
  input.dataset.paramName = paramName;
  input.dataset.required = String(required);
  input.dataset.paramKind = "num";
  input.setAttribute("aria-label", paramName);
  if (initialValue !== null && initialValue !== undefined) {
    input.value = String(initialValue);
  } else if (defaultValue !== null && defaultValue !== undefined) {
    input.placeholder = String(defaultValue);
  }
  if (allowFloat) {
    input.addEventListener("input", () => {
      input.value = input.value.replace(/[^0-9.]/g, "").replace(/(\..*)\./g, "$1");
      updateSubmitState();
    });
  } else {
    input.addEventListener("input", () => {
      input.value = input.value.replace(/\D/g, "");
      updateSubmitState();
    });
  }
  input.addEventListener("blur", updateSubmitState);
  return input;
}

function createSingleSelect({ slug, paramName, options, defaultValue, required, initialValue = null }) {
  const select = document.createElement("select");
  select.className = "rule-param single-param";
  select.dataset.ruleSlug = slug;
  select.dataset.paramName = paramName;
  select.dataset.required = String(required);
  select.dataset.paramKind = "single";
  select.setAttribute("aria-label", paramName);

  const empty = document.createElement("option");
  empty.value = "";
  empty.textContent = "";
  select.appendChild(empty);

  for (const optionValue of options) {
    const option = document.createElement("option");
    option.value = optionValue;
    option.textContent = optionValue;
    select.appendChild(option);
  }

  const valueToSet = initialValue !== null ? String(initialValue) : (defaultValue !== null && defaultValue !== undefined ? String(defaultValue) : null);
  if (valueToSet !== null) select.value = valueToSet;
  select.addEventListener("change", updateSubmitState);
  return select;
}

function createMultiSelect({ slug, paramName, options, defaultValues, required, initialValues = null }) {
  const root = document.createElement("span");
  root.className = "multi-select";
  root.dataset.ruleSlug = slug;
  root.dataset.paramName = paramName;
  root.dataset.required = String(required);
  root.dataset.paramKind = "multi";

  const selected = new Set(initialValues !== null ? initialValues.map(String) : defaultValues);
  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = "multi-trigger";
  trigger.setAttribute("aria-label", paramName);
  trigger.setAttribute("aria-haspopup", "listbox");
  trigger.setAttribute("aria-expanded", "false");

  const label = document.createElement("span");
  label.className = "multi-label";
  trigger.appendChild(label);

  const menu = document.createElement("div");
  menu.className = "multi-menu";
  menu.setAttribute("role", "listbox");
  menu.setAttribute("aria-multiselectable", "true");

  function sync() {
    const values = Array.from(selected);
    root.dataset.value = values.join("\u001f");
    label.textContent = values[0] || "";
    label.classList.toggle("empty", values.length === 0);
    for (const option of menu.querySelectorAll(".multi-option")) {
      const isSelected = selected.has(option.dataset.value);
      option.classList.toggle("selected", isSelected);
      option.setAttribute("aria-selected", String(isSelected));
    }
    updateSubmitState();
  }

  for (const optionValue of options) {
    const option = document.createElement("button");
    option.type = "button";
    option.className = "multi-option";
    option.dataset.value = optionValue;
    option.setAttribute("role", "option");

    const check = document.createElement("span");
    check.className = "multi-check";
    check.textContent = "✓";

    const text = document.createElement("span");
    text.textContent = optionValue;

    option.append(check, text);
    option.addEventListener("click", (event) => {
      event.stopPropagation();
      if (selected.has(optionValue)) selected.delete(optionValue);
      else selected.add(optionValue);
      sync();
    });
    menu.appendChild(option);
  }

  trigger.addEventListener("click", (event) => {
    event.stopPropagation();
    const nextOpen = !root.classList.contains("open");
    closeAllMultiSelects(root);
    root.classList.toggle("open", nextOpen);
    trigger.setAttribute("aria-expanded", String(nextOpen));
  });

  root.append(trigger, menu);
  sync();
  return root;
}

function closeAllMultiSelects(except = null) {
  for (const root of document.querySelectorAll(".multi-select.open")) {
    if (root === except) continue;
    root.classList.remove("open");
    root.querySelector(".multi-trigger")?.setAttribute("aria-expanded", "false");
  }
}

document.addEventListener("click", () => closeAllMultiSelects());
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeAllMultiSelects();
});

function createParameterControl(slug, paramName, config, initialValue = null) {
  const required = config.default === null;
  const type = String(config.type || "");

  if (type === "num" || type === "float" || type === "int" || type === "integer") {
    return createNumericInput({
      slug,
      paramName,
      defaultValue: config.default,
      required,
      allowFloat: type === "float" || type === "num",
      initialValue,
    });
  }

  const options = getLiteralOptions(type);
  const multi = config.mult_select === true;
  if (multi) {
    return createMultiSelect({
      slug,
      paramName,
      options,
      defaultValues: normalizeListDefault(config.default, true),
      required,
      initialValues: initialValue !== null ? normalizeListDefault(initialValue, true) : null,
    });
  }

  return createSingleSelect({
    slug,
    paramName,
    options,
    defaultValue: normalizeListDefault(config.default, false)[0],
    required,
    initialValue: initialValue !== null ? String(initialValue) : null,
  });
}

function appendDescriptionWithControls(container, slug, rule, storedParams = {}) {
  const params = getRuleParameters(rule);
  const descriptionParts = [String(rule.description || "")];
  if (isStatefulRule(rule)) {
    descriptionParts.push(" Disabled after {STATEFUL_TIMES} operations.");
  }

  const fullDescription = descriptionParts.join("");
  const placeholderRe = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;
  let lastIndex = 0;
  let match;

  while ((match = placeholderRe.exec(fullDescription)) !== null) {
    if (match.index > lastIndex) {
      container.appendChild(document.createTextNode(fullDescription.slice(lastIndex, match.index)));
    }

    const paramName = match[1];
    if (paramName === "STATEFUL_TIMES" && isStatefulRule(rule)) {
      container.appendChild(createNumericInput({
        slug,
        paramName,
        defaultValue: getDefaultStatefulCount(rule),
        required: false,
        initialValue: storedParams.STATEFUL_TIMES ?? null
      }));
    } else if (params[paramName]) {
      container.appendChild(createParameterControl(slug, paramName, params[paramName], storedParams[paramName] ?? null));
    } else {
      container.appendChild(document.createTextNode(match[0]));
    }

    lastIndex = placeholderRe.lastIndex;
  }

  if (lastIndex < fullDescription.length) {
    container.appendChild(document.createTextNode(fullDescription.slice(lastIndex)));
  }
}

/**
 * Render the rules list with toggles.
 */
function renderRulesList(domain, rulesMap, preselectedSlugs = [], storedParams = {}) {
  const container = qs("#rules");
  container.innerHTML = "";

  const slugs = Object.keys(rulesMap).sort();
  if (slugs.length === 0) {
    container.innerHTML = `<div class="muted">No policies available for <b>${domain}</b>.</div>`;
    return;
  }

  for (const slug of slugs) {
    const id = `rule_${slug}`;
    const rule = rulesMap[slug];
    const row = document.createElement("div");
    row.className = "rule-row";

    const description = document.createElement("div");
    description.className = "rule-name";
    appendDescriptionWithControls(description, slug, rule, storedParams[slug] || {});

    const toggle = document.createElement("label");
    toggle.className = "toggle";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.id = id;
    checkbox.checked = preselectedSlugs.includes(slug);
    checkbox.addEventListener("change", updateSubmitState);

    const slider = document.createElement("span");
    slider.className = "slider";

    toggle.append(checkbox, slider);
    row.append(description, toggle);
    row.dataset.ruleSlug = slug;
    row.dataset.hasArguments = String(hasRuleArguments(rule));
    container.appendChild(row);
  }

  updateSubmitState();
}

/**
 * Gather selected rule slugs from the UI.
 */
function getSelectedSlugs() {
  const boxes = Array.from(document.querySelectorAll('.rule-row input[type="checkbox"]'));
  return boxes.filter(cb => cb.checked).map(cb => cb.id.replace(/^rule_/, ""));
}

function getRequiredArgumentErrors() {
  const errors = [];
  for (const row of document.querySelectorAll(".rule-row")) {
    const checkbox = row.querySelector('.toggle input[type="checkbox"]');
    const selected = checkbox?.checked;
    row.classList.remove("invalid");
    for (const control of row.querySelectorAll("[data-required='true']")) {
      control.classList.remove("param-required");
    }
    if (!selected) continue;

    for (const control of row.querySelectorAll("[data-required='true']")) {
      let hasValue = false;
      if (control.dataset.paramKind === "multi") {
        hasValue = Boolean(control.dataset.value);
      } else {
        hasValue = Boolean((control.value || "").trim());
      }

      if (!hasValue) {
        row.classList.add("invalid");
        control.classList.add("param-required");
        errors.push({
          slug: row.dataset.ruleSlug,
          paramName: control.dataset.paramName
        });
      }
    }
  }
  return errors;
}

function updateSubmitState() {
  const submitBtn = document.getElementById("submit-btn");
  if (!submitBtn) return;
  const errors = getRequiredArgumentErrors();
  submitBtn.disabled = errors.length > 0;

  const status = document.getElementById("status");
  if (errors.length === 0 && status?.textContent.startsWith("Please fill in the required arguments")) {
    status.classList.remove("error");
  }
}

// Read current parameter values from all UI controls.
// Returns { slug -> { paramName -> rawValue } }
function collectParameterValues() {
  const values = {};
  for (const control of document.querySelectorAll("[data-rule-slug][data-param-name]")) {
    const slug = control.dataset.ruleSlug;
    const paramName = control.dataset.paramName;
    if (!values[slug]) values[slug] = {};
    if (control.dataset.paramKind === "multi") {
      const raw = control.dataset.value || "";
      values[slug][paramName] = raw ? raw.split("") : [];
    } else {
      values[slug][paramName] = (control.value || "").trim() || null;
    }
  }
  return values;
}

// Convert a raw string value from a UI control to the correct JS type.
function coerceParamValue(paramConfig, rawValue) {
  if (rawValue === null || rawValue === undefined || rawValue === "") {
    return paramConfig.default ?? null;
  }
  const type = String(paramConfig.type || "");
  if (type === "float" || type === "num") return parseFloat(rawValue);
  if (type === "int" || type === "integer") return parseInt(rawValue, 10);
  if (paramConfig.mult_select) return Array.isArray(rawValue) ? rawValue : [rawValue].filter(Boolean);
  return rawValue;
}

// Extract stored concrete parameter values from a previously saved policy.
// Returns { slug -> { paramName -> value } } for condition rules.
function extractStoredParamValues(storedPolicy, rulesMap) {
  if (!storedPolicy?.rules) return {};
  const result = {};
  for (const rule of storedPolicy.rules) {
    if (rule.effect !== "condition" || !rule.condition?.parameters) continue;
    const conditionName = rule.condition.name;
    const slug = Object.entries(rulesMap).find(([, r]) => r.condition?.name === conditionName)?.[0];
    if (slug) result[slug] = rule.condition.parameters;
  }
  return result;
}

function extractStoredStatefulValues(existingEntry) {
  const result = {};
  const stored = existingEntry?.stateful_policies || {};
  for (const [slug, state] of Object.entries(stored)) {
    if (!state || typeof state !== "object") continue;
    const value = state.remaining ?? state.initial;
    if (value !== null && value !== undefined) {
      result[slug] = { STATEFUL_TIMES: value };
    }
  }
  return result;
}

/**
 * Compile the final policy by inserting selected rules into the template.
 */
function compilePolicy(template, rulesMap, selectedSlugs, paramValues = {}) {
  const policy = JSON.parse(JSON.stringify(template)); // deep clone
  policy.rules = selectedSlugs.map(slug => {
    const rule = JSON.parse(JSON.stringify(rulesMap[slug]));
    // For condition rules, replace the parameter schema with concrete user-supplied values.
    if (rule.effect === "condition" && rule.condition?.parameters) {
      const slugParams = paramValues[slug] || {};
      const filledParams = {};
      for (const [paramName, config] of Object.entries(rule.condition.parameters)) {
        filledParams[paramName] = coerceParamValue(config, slugParams[paramName]);
      }
      rule.condition.parameters = filledParams;
    }
    return rule;
  });
  return policy;
}

function getStatefulCount(rule, rawValue) {
  if (rawValue === null || rawValue === undefined || rawValue === "") {
    return getDefaultStatefulCount(rule);
  }
  const parsed = parseInt(rawValue, 10);
  if (!Number.isFinite(parsed)) return getDefaultStatefulCount(rule);
  return Math.max(0, parsed);
}

/**
 * Produce target_requests by evaluating the policy across all sitemap endpoints.
 *
 * Inputs/outputs unchanged:
 *  - input: (policyObj, sitemapObj)
 *  - output: [{ url, method, decision, (optional) body }]
 */
function computeTargetRequests(policyObj, sitemapObj, rulesMap = {}, selectedSlugs = [], paramValues = {}) {
  const rules = Array.isArray(policyObj?.rules) ? policyObj.rules : [];
  const sitemapEntries = Array.isArray(sitemapObj) ? sitemapObj : (Array.isArray(sitemapObj?.entries) ? sitemapObj.entries : sitemapObj);

  if (!Array.isArray(sitemapEntries)) {
    throw new Error("Invalid sitemapObj: expected an array of sitemap entries.");
  }

  const allowedActions = new Set();
  const conditionRulesByAction = new Map();
  const statefulRulesByAction = new Map();
  const stateful_policies = {};

  for (const slug of selectedSlugs) {
    const rawRule = rulesMap[slug];
    if (!isStatefulRule(rawRule)) continue;

    const actions = Array.isArray(rawRule.action) ? rawRule.action : (rawRule.action ? [rawRule.action] : []);
    const count = getStatefulCount(rawRule, paramValues[slug]?.STATEFUL_TIMES);
    stateful_policies[slug] = {
      slug,
      initial: count,
      remaining: count,
      actions,
      exhausted: count <= 0,
    };
    for (const action of actions) {
      if (typeof action === "string" && action) {
        statefulRulesByAction.set(action, slug);
      }
    }
  }

  for (const rule of rules) {
    if (!rule || typeof rule !== "object") continue;
    const effect = String(rule.effect || "").toLowerCase();
    const actions = Array.isArray(rule.action) ? rule.action : (rule.action ? [rule.action] : []);

    if (effect === "allow") {
      for (const a of actions) if (typeof a === "string" && a) allowedActions.add(a);
    } else if (effect === "condition") {
      for (const a of actions) if (typeof a === "string" && a) conditionRulesByAction.set(a, rule);
    }
  }

  const target_requests = [];
  const condition_requests = [];
  const stateful_requests = [];

  for (const entry of sitemapEntries) {
    if (!entry || typeof entry !== "object") continue;

    const method = String(entry.method || "").toUpperCase();
    const urlTemplate = entry.url;
    const body = entry.body || {};
    const semanticAction = entry.semantic_action;

    if (!method || !urlTemplate) continue;

    if (typeof semanticAction === "string" && allowedActions.has(semanticAction)) {
      const statefulSlug = statefulRulesByAction.get(semanticAction);
      if (statefulSlug) {
        const target = {
          url: urlTemplate,
          method,
          action: semanticAction,
          rule_slug: statefulSlug,
          decision: "stateful_allow",
        };
        if (entry.resource_type) target.resource_type = entry.resource_type;
        if (body && typeof body === "object" && Object.keys(body).length > 0) target.body = body;
        stateful_requests.push(target);
      }
      continue;
    }

    if (typeof semanticAction === "string" && conditionRulesByAction.has(semanticAction)) {
      const rule = conditionRulesByAction.get(semanticAction);
      const cond = rule.condition;
      if (!cond || typeof cond.name !== "string" || !cond.name ||
          !Array.isArray(cond.args) || typeof cond.parameters !== "object" || cond.parameters === null) {
        console.warn("[edit] Condition rule has invalid condition for action:", semanticAction, rule);
        continue;
      }
      condition_requests.push({
        url: urlTemplate,
        method,
        action: semanticAction,
        condition: rule.condition, // { name, args, parameters: { max_amount: 1 } }
        rule_slug: statefulRulesByAction.get(semanticAction) || null,
      });
      continue;
    }

    // Default: deny
    const target = { url: urlTemplate, method, decision: "deny" };
    if (body && typeof body === "object" && Object.keys(body).length > 0) target.body = body;
    target_requests.push(target);
  }

  return { target_requests, condition_requests, stateful_requests, stateful_policies };
}

/**
 * Show an error or info message in #status.
 */
function setStatus(html, { error = false } = {}) {
  const status = qs("#status");
  status.innerHTML = html;
  status.classList.toggle("error", error);
}

(async function main() {
  const backBtn = document.getElementById("back-btn");
  const submitBtn = document.getElementById("submit-btn");

  const params = new URLSearchParams(location.search);
  const forcedDomain = params.get("domain");

  backBtn.addEventListener("click", () => window.close());

  // Pick domain: URL param > current tab
  const domain = forcedDomain || await getCurrentDomain();
  // For webarena instances, load bundled resources by port-mapped domain
  // but keep the original origin as the storage key.
  const resourceDomain = getResourceDomain(domain);

  // Load any existing entry for this domain
  const stored = await new Promise((res, rej) =>
    chrome.storage.local.get(domain, r => chrome.runtime.lastError ? rej(chrome.runtime.lastError) : res(r)));
  const existingEntry = stored[domain] || null;
  const existingPolicy = existingEntry?.policy || null;
  const storedSlugs = existingEntry?.selected_rule_slugs || [];

  // Attempt to load resources for the (possibly forced) domain
  let resources;
  try {
    resources = await loadDomainResources(resourceDomain);
  } catch (e) {
    setStatus(`Policy setup is unavailable for <b>${domain}</b> as resources for this domain are not found.`);
    submitBtn.disabled = true;
    return;
  }

  const { template, rulesMap, sitemap } = resources;

  // If we're updating, preselect based on current policy; otherwise empty selection
  const preselected = inferSelectedSlugs(existingPolicy, rulesMap, storedSlugs);
  if (existingPolicy) {
    setStatus(`Updating policy for <b>${domain}</b>. Toggle on desired policies below and press Submit.`);
  } else {
    setStatus(`Please select policies for <b>${domain}</b>.`);
  }

  // Restore stored parameter values for condition rules (if editing an existing policy)
  const storedParamValues = {
    ...extractStoredParamValues(existingPolicy, rulesMap),
    ...extractStoredStatefulValues(existingEntry),
  };

  // Initial render (plain list)
  renderRulesList(domain, rulesMap, preselected, storedParamValues);

  // Submit button logic
  submitBtn.addEventListener("click", async () => {
    const argumentErrors = getRequiredArgumentErrors();
    if (argumentErrors.length > 0) {
      setStatus("Please fill in the required arguments for selected policies.", { error: true });
      return;
    }

    submitBtn.disabled = true; // gray out to prevent double-submit

    try {
      const selected = getSelectedSlugs();
      const paramValues = collectParameterValues();
      const compiledPolicy = compilePolicy(template, rulesMap, selected, paramValues);
      const { target_requests, condition_requests, stateful_requests, stateful_policies } =
        computeTargetRequests(compiledPolicy, sitemap, rulesMap, selected, paramValues);

      const payload = {
        policy: compiledPolicy,
        selected_rule_slugs: selected,
        target_requests,
        condition_requests,
        stateful_requests,
        stateful_policies,
        sitemap,
      };

      await storageSet({ [domain]: payload });

      setStatus(`Policy for <b>${domain}</b> successfully updated.`);
      updateSubmitState();
    } catch (err) {
      console.error(err);
      setStatus(`Failed to update policy: ${String(err.message || err)}`, { error: true });
      updateSubmitState(); // re-enable to allow retry if the form is valid
    }
  });
})();
