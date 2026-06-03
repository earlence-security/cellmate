// ====== CONFIG / HELPERS =====================================================

const EXT_ORIGIN = `chrome-extension://${chrome.runtime.id}`;

// Turn a template URL (supports {param} and *) into a RegExp
//   - {param}  -> matches one path segment ([^/]+)
//   - *        -> matches anything (.*)
function compileTemplateToRegex(template) {
  let pattern = template.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  pattern = pattern
    .replace(/\\\{[a-zA-Z_][a-zA-Z0-9_]*\\\}/g, "([^/]+)")
    .replace(/\\\*/g, ".*");
  return new RegExp(`^${pattern}$`);
}

function hostnameOf(url) {
  try { return new URL(url).hostname; } catch { return ""; }
}

// Policy domain match: exact or subdomain (foo.example.com matches example.com)
function domainMatches(policyDomain, urlHostname) {
  if (!policyDomain || !urlHostname) return false;
  if (policyDomain === urlHostname) return true;
  return urlHostname.endsWith("." + policyDomain);
}

function isFromExtension(details) {
  return (
    details.initiator === EXT_ORIGIN ||
    details.originUrl === EXT_ORIGIN ||
    (details.tabId === -1 && details.initiator?.startsWith("chrome-extension://"))
  );
}

// ====== TARGET STORE =========================================================
//
// targetsByDomain holds static targets (deny / allow_public), condition-based
// targets (decision: "condition"), and stateful targets (decision: "stateful_allow").
//
// Static entry:
//   { method, rawUrl, regex, decision: "allow"|"deny"|"allow_public", bodyPattern }
//
// Condition entry:
//   { method, rawUrl, regex, decision: "condition", condition: { name, parameters, resolvedArgs } }
//   resolvedArgs: pre-looked-up from sitemap at compile time — no argSpecMap needed at enforcement time
//
// Stateful entry:
//   { method, rawUrl, regex, decision: "stateful_allow", rule_slug, bodyPattern }
const targetsByDomain = Object.create(null);

// In-memory remaining counts for stateful policies: { domain -> { slug -> { initial, remaining, exhausted } } }
const statefulStateByDomain = Object.create(null);

// Global caches for function execution and DOM snapshot storage.
self.funcCache = self.funcCache || new Map();
self.snapshots = self.snapshots || new Map();

function compileStaticTarget(t) {
  return {
    method:        (t.method || "").toUpperCase(),
    rawUrl:        t.url,
    regex:         compileTemplateToRegex(t.url),
    decision:      t.decision,
    bodyPattern:   t.body || null,
    resourceType: t.resource_type || null,
  };
}

function compileStatefulTarget(t) {
  return {
    method:       (t.method || "").toUpperCase(),
    rawUrl:       t.url,
    regex:        compileTemplateToRegex(t.url),
    decision:     "stateful_allow",
    rule_slug:    t.rule_slug,
    bodyPattern:  t.body || null,
    resourceType: t.resource_type || null,
  };
}

// Pre-resolve arg sources from sitemap so the compiled entry is self-contained.
function compileConditionTarget(c, sitemap) {
  const cond = c.condition;
  if (!cond || typeof cond.name !== "string" || !cond.name ||
      !Array.isArray(cond.args) || typeof cond.parameters !== "object" || cond.parameters === null) {
    console.error("[bg] condition_request has invalid condition, skipping:", c);
    return null;
  }
  const sitemapEntry = (sitemap || []).find((s) => s.semantic_action === c.action);
  const resolvedArgs = {};
  for (const argName of (c.condition?.args || [])) {
    const spec = sitemapEntry?.args?.[argName];
    if (spec) resolvedArgs[argName] = spec; // { type, source: { type, url, selector } }
  }

  return {
    method:        (c.method || "").toUpperCase(),
    rawUrl:        c.url,
    regex:         compileTemplateToRegex(c.url),
    decision:      "condition",
    rule_slug:     c.rule_slug || null,
    resourceType: sitemapEntry?.resource_type || null,
    condition: {
      name:         c.condition.name,
      parameters:   c.condition.parameters,
      resolvedArgs, // pre-looked-up — no sitemap or action needed at enforcement time
    },
  };
}

// Build/replace one domain's compiled target list.
// Returns a Promise that resolves when JS condition functions are preloaded.
function setDomainTargets(domain, targetRequests = [], conditionRequests = [], sitemap = [], statefulRequests = [], statefulPolicies = {}) {
  const compiledConditions = conditionRequests.map((c) => compileConditionTarget(c, sitemap)).filter(Boolean);
  const compiledStateful = statefulRequests.map(compileStatefulTarget);

  targetsByDomain[domain] = [
    ...targetRequests.map(compileStaticTarget),
    ...compiledConditions,
    ...compiledStateful,
  ];

  // Sync in-memory stateful state from storage values.
  if (!statefulStateByDomain[domain]) statefulStateByDomain[domain] = {};
  const domainState = statefulStateByDomain[domain];
  // Remove slugs no longer present in stateful_policies.
  for (const slug of Object.keys(domainState)) {
    if (!(slug in statefulPolicies)) delete domainState[slug];
  }
  // Add or update remaining slugs.
  for (const [slug, policy] of Object.entries(statefulPolicies)) {
    domainState[slug] = {
      initial:   policy.initial ?? 1,
      remaining: policy.remaining ?? policy.initial ?? 1,
      exhausted: policy.exhausted ?? false,
    };
  }

  // Preload JS condition functions (async).
  const functionPaths = [...new Set(
    compiledConditions
      .filter((e) => e.condition?.name)
      .map((e) => constructFunctionPath(domain, e.condition.name))
  )];

  console.log("[bg] setDomainTargets:", domain, targetsByDomain[domain].length, "entries");

  return functionPaths.length > 0
    ? preloadFunctions(functionPaths, self.funcCache)
    : Promise.resolve();
}

function removeDomainTargets(domain) {
  delete targetsByDomain[domain];
  delete statefulStateByDomain[domain];
  console.log("[bg] removeDomainTargets:", domain);
}

// ====== CONDITION ENFORCEMENT ================================================

function handleConditionRequest(details, domain, match, bodyObj) {
  const { name, parameters, resolvedArgs } = match.condition;

  // Build function input from pre-resolved arg sources (DOM or request body).
  const input = {};
  for (const [argName, spec] of Object.entries(resolvedArgs || {})) {
    const source = spec.source || {};
    let raw;
    if (source.type === "dom") {
      raw = getCachedSnapshot(details.tabId, source.url, source.selector, self.snapshots);
      if (raw === null) {
        console.error("[bg] No DOM snapshot for", argName, "selector:", source.selector);
        return { cancel: true };
      }
    } else if (source.type === "request_body") {
      raw = getNestedValue(bodyObj, source.path);
      if (raw === undefined || raw === null) {
        console.error("[bg] No request body value for", argName, "path:", source.path);
        return { cancel: true };
      }
    } else {
      console.warn("[bg] Unsupported arg source type:", source.type, "for", argName);
      continue;
    }
    if (spec.type === "number") {
      const parsed = parseFloat(String(raw).replace(/[^0-9.-]+/g, ""));
      if (isNaN(parsed)) {
        console.error("[bg] Cannot parse number for", argName, ":", raw);
        return { cancel: true };
      }
      input[argName] = parsed;
    } else {
      input[argName] = raw;
    }
  }

  const allowed = executeFunction(domain, { name, parameters }, input, self.funcCache);
  console.log(`[bg] Condition ${name}: ${allowed ? "ALLOW" : "DENY"}`);
  if (allowed && match.rule_slug) {
    return handleStatefulRequest(details, domain, match);
  }
  return allowed ? {} : { cancel: true };
}

// ====== STATEFUL ENFORCEMENT =================================================

function handleStatefulRequest(details, domain, match) {
  const state = (statefulStateByDomain[domain] || {})[match.rule_slug];
  if (!state || state.exhausted || state.remaining <= 0) {
    console.log("[bg] DENY (stateful exhausted):", details.method, details.url);
    return { cancel: true };
  }

  state.remaining -= 1;
  if (state.remaining <= 0) {
    state.remaining = 0;
    state.exhausted = true;
    console.log("[bg] Stateful policy exhausted:", match.rule_slug, "domain:", domain);
  }
  console.log("[bg] ALLOW (stateful, remaining:", state.remaining, "):", details.method, details.url);

  persistStatefulState(domain);
  return {};
}

// Persist current in-memory stateful state back to chrome.storage.local.
// Reads the stored entry, overlays the latest in-memory remaining/exhausted values,
// and removes exhausted slugs from selected_rule_slugs so the edit page reflects the change.
function persistStatefulState(domain) {
  chrome.storage.local.get(domain, (stored) => {
    if (chrome.runtime.lastError) {
      console.warn("[bg] persistStatefulState get error:", chrome.runtime.lastError);
      return;
    }
    const entry = stored[domain];
    if (!entry) return;

    // Snapshot current in-memory state at the time of the write (handles rapid requests correctly).
    const currentState = statefulStateByDomain[domain] || {};

    const updatedPolicies = { ...(entry.stateful_policies || {}) };
    for (const [slug, s] of Object.entries(currentState)) {
      if (updatedPolicies[slug]) {
        updatedPolicies[slug] = { ...updatedPolicies[slug], remaining: s.remaining, exhausted: s.exhausted };
      }
    }

    const exhaustedSlugs = new Set(
      Object.entries(currentState).filter(([, s]) => s.exhausted).map(([slug]) => slug)
    );
    const updatedSlugs = (entry.selected_rule_slugs || []).filter(slug => !exhaustedSlugs.has(slug));

    chrome.storage.local.set(
      { [domain]: { ...entry, stateful_policies: updatedPolicies, selected_rule_slugs: updatedSlugs } },
      () => { if (chrome.runtime.lastError) console.warn("[bg] persistStatefulState set error:", chrome.runtime.lastError); }
    );
  });
}

// ====== STORAGE LOAD / SYNC ==================================================

function loadAllFromStorage() {
  chrome.storage.local.get(null, (all) => {
    if (chrome.runtime.lastError) {
      console.warn("[bg] storage load error:", chrome.runtime.lastError);
      return;
    }

    const loads = [];
    for (const [key, value] of Object.entries(all || {})) {
      if (!value) continue;
      loads.push(
        setDomainTargets(key, value.target_requests || [], value.condition_requests || [], value.sitemap || [], value.stateful_requests || [], value.stateful_policies || {})
          .catch((err) => console.error("[bg] function preload failed:", key, err))
      );
    }

    Promise.all(loads).then(() => {
      startDomMonitoring(self.snapshots);
      console.log("[bg] loaded policies for", Object.keys(targetsByDomain).length, "domain(s)");
    });
  });
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;

  for (const [k, delta] of Object.entries(changes)) {
    const val = delta.newValue;
    if (val === undefined) {
      removeDomainTargets(k);
      continue;
    }
    setDomainTargets(k, val.target_requests || [], val.condition_requests || [], val.sitemap || [], val.stateful_requests || [], val.stateful_policies || {})
      .catch((err) => console.error("[bg] function preload failed:", k, err));
  }
});

// ====== MATCHING =============================================================

// Returns { match, domain } or null.
function findTargetForRequest(hostname, method, url, parsedBody, requestType) {
  method = (method || "").toUpperCase();

  for (const [policyDomain, entries] of Object.entries(targetsByDomain)) {
    if (!domainMatches(policyDomain, hostname)) continue;

    for (const entry of entries) {
      if (entry.method && entry.method !== method) continue;
      if (!entry.regex.test(url)) continue;
      if (entry.bodyPattern && !deepContains(entry.bodyPattern, parsedBody || {})) continue;
      if (entry.resourceType && entry.resourceType !== requestType) continue;
      return { match: entry, domain: policyDomain };
    }
  }
  return null;
}

function parseRequestBody(details) {
  const rb = details.requestBody;
  if (!rb) return null;

  if (rb.formData) {
    const obj = {};
    for (const [k, arr] of Object.entries(rb.formData)) {
      obj[k] = arr.length === 1 ? arr[0] : arr.slice();
    }
    return obj;
  }

  if (rb.raw && rb.raw.length > 0 && rb.raw[0].bytes) {
    try {
      const dec = new TextDecoder("utf-8");
      const str = dec.decode(new Uint8Array(rb.raw[0].bytes));
      try {
        return JSON.parse(str);
      } catch {
        if (str.includes("=")) {
          const params = new URLSearchParams(str);
          const obj = {};
          for (const [k, v] of params.entries()) {
            if (k in obj) {
              obj[k] = Array.isArray(obj[k]) ? [...obj[k], v] : [obj[k], v];
            } else {
              obj[k] = v;
            }
          }
          return obj;
        }
        return { _raw: str };
      }
    } catch {
      return null;
    }
  }
  return null;
}

function getNestedValue(obj, path) {
  if (!obj || !path) return undefined;
  return path.split(".").reduce((cur, key) => (cur != null ? cur[key] : undefined), obj);
}

function deepContains(pattern, target) {
  if (pattern === null || pattern === undefined) return true;
  if (target === null || target === undefined) return false;

  const isObj = v => typeof v === "object" && v !== null;
  if (!isObj(pattern)) return Object.is(pattern, target);

  if (Array.isArray(pattern)) {
    if (!Array.isArray(target)) return false;
    return pattern.every(pItem =>
      target.some(tItem =>
        (isObj(pItem) || isObj(tItem))
          ? JSON.stringify(pItem) === JSON.stringify(tItem)
          : Object.is(pItem, tItem)
      )
    );
  }

  if (!isObj(target)) return false;
  for (const [k, v] of Object.entries(pattern)) {
    if (!(k in target)) return false;
    if (!deepContains(v, target[k])) return false;
  }
  return true;
}

// ====== ENFORCEMENT ==========================================================

const pendingActionsByRequestId = new Map();

chrome.webRequest.onBeforeRequest.addListener(
  function onBeforeRequest(details) {
    if (isFromExtension(details)) return {};

    const destHostname = hostnameOf(details.url);
    const method = details.method;
    const bodyObj = parseRequestBody(details);

    const result = findTargetForRequest(destHostname, method, details.url, bodyObj, details.type);
    if (result) {
      const { match, domain } = result;
      if (match.decision === "deny") {
        console.log("[bg] DENY:", method, details.url, "matched", match.rawUrl);
        return { cancel: true };
      }
      if (match.decision === "allow_public") {
        pendingActionsByRequestId.set(details.requestId, "allow_public");
        return {};
      }
      if (match.decision === "condition") {
        return handleConditionRequest(details, domain, match, bodyObj);
      }
      if (match.decision === "stateful_allow") {
        return handleStatefulRequest(details, domain, match);
      }
    }

    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestBody"]
);

chrome.webRequest.onBeforeSendHeaders.addListener(
  function onBeforeSendHeaders(details) {
    if (isFromExtension(details) || pendingActionsByRequestId.get(details.requestId) !== "allow_public") {
      return { requestHeaders: details.requestHeaders };
    }
    const filtered = (details.requestHeaders || []).filter(
      (h) => h.name.toLowerCase() !== "cookie"
    );
    console.log("[bg] Stripped Cookie for", details.method, details.url);
    return { requestHeaders: filtered };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders", "extraHeaders"]
);

const clearPending = (details) => pendingActionsByRequestId.delete(details.requestId);
chrome.webRequest.onCompleted.addListener(clearPending, { urls: ["<all_urls>"] });
chrome.webRequest.onErrorOccurred.addListener(clearPending, { urls: ["<all_urls>"] });
chrome.webRequest.onBeforeRedirect.addListener(clearPending, { urls: ["<all_urls>"] });

// ====== BOOTSTRAP ============================================================

loadAllFromStorage();