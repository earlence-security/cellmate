// ====== CONFIG / HELPERS =====================================================

const EXT_ORIGIN = `chrome-extension://${chrome.runtime.id}`;

// Turn a template URL (supports {param} and *) into a RegExp
//   - {param}  -> matches one path segment ([^/]+)
//   - *        -> matches anything (.*)
function compileTemplateToRegex(template) {
  // 1) Escape regex metacharacters
  let pattern = template.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // 2) Translate placeholders and wildcards
  pattern = pattern
    .replace(/\\\{[a-zA-Z_][a-zA-Z0-9_]*\\\}/g, "([^/]+)") // \{name\} -> ([^/]+)
    .replace(/\\\*/g, ".*");                               // \* -> .*
  return new RegExp(`^${pattern}$`);
}

// Return host name from URL, or "" if invalid
function hostnameOf(url) {
  try { return new URL(url).hostname; } catch { return ""; }
}

// Policy domain match: exact or subdomain (foo.example.com matches example.com)
function domainMatches(policyDomain, urlHostname) {
  if (!policyDomain || !urlHostname) return false;
  if (policyDomain === urlHostname) return true;
  return urlHostname.endsWith("." + policyDomain);
}

// Is a request from our extension context?
function isFromExtension(details) {
  return (
    details.initiator === EXT_ORIGIN ||
    details.originUrl === EXT_ORIGIN || // older Chromium
    (details.tabId === -1 && details.initiator?.startsWith("chrome-extension://"))
  );
}

// ====== DATA STRUCTS AND RELATED FUNCTIONS ==================================

// ====== For determining the "current domain" =======

// Map tabId -> top-level page hostname ("current domain" for that tab)
const tabTopDomains = new Map();

// Keep this map fresh on navigations / URL changes
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    const host = hostnameOf(changeInfo.url);
    if (host) tabTopDomains.set(tabId, host);
  }
});

// Cleanup on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  tabTopDomains.delete(tabId);
});

// ====== Predicted allowlist (domain restriction) =======
// Evaluated FIRST, before untrusted & target matches.
let predictedAllowlistActive = false;     // storage: predicted_domain_allowlist_active
let predictedAllowlist = new Set();       // storage: predicted_domain_allowlist (exact hostnames)

// ====== For storing target urls to apply enforcement per domain =======
//
// targetsByDomain = {
//   "gitlab.com": [
//     { method: "POST", rawUrl: "...", regex: /.../, decision: "deny", bodyPattern: {...} },
//     ...
//   ],
//   ...
// }
const targetsByDomain = Object.create(null);

// Build/replace one domain's compiled target list
function setDomainTargets(domain, targetRequests = []) {
  const compiled = targetRequests.map((t) => ({
    method: (t.method || "").toUpperCase(),
    rawUrl: t.url,
    regex: compileTemplateToRegex(t.url),
    decision: t.decision,     // "deny" | "allow_public"
    bodyPattern: t.body || null
  }));
  targetsByDomain[domain] = compiled;
  console.log("[bg] setDomainTargets:", domain, compiled.length, "entries");
}

// Remove a domain entirely
function removeDomainTargets(domain) {
  delete targetsByDomain[domain];
  console.log("[bg] removeDomainTargets:", domain);
}

let disallowUntrusted = true; // factory default: block all requests to domains without a policy

// ====== For storing policies per domain =======
// (currently only used to figure out which domains are explicitly allowed via policy)
const policiesByDomain = Object.create(null);

function setPolicyForDomain(domain, policyObj) {
  const allowed = new Set((policyObj?.allowed_domains || []).map(String));
  policiesByDomain[domain] = { allowedDomains: allowed, hasPolicy: true };
}

function removePolicyForDomain(domain) {
  delete policiesByDomain[domain];
}

// Helper: does the current page's policy allow the destination via allowed_domains?
function currentPolicyAllowsDest(currentDomain, destHostname) {
  if (!currentDomain) return false;
  const rec = policiesByDomain[currentDomain];
  if (!rec) return false;
  const allowedSet = rec.allowedDomains || new Set();
  return Array.from(allowedSet).some(ad => domainMatches(ad, destHostname));
}

// ====== Load resources from storage during startup ======

function loadAllFromStorage() {
  chrome.storage.local.get(null, (all) => {
    if (chrome.runtime.lastError) {
      console.warn("[bg] storage load error:", chrome.runtime.lastError);
      return;
    }

    // untrusted-domain toggle
    if (typeof all.disallow_untrusted_domains === "boolean") {
      disallowUntrusted = all.disallow_untrusted_domains;
    } else {
      chrome.storage.local.set({ disallow_untrusted_domains: true });
      disallowUntrusted = true;
    }

    // predicted allowlist gate
    predictedAllowlistActive = !!all.predicted_domain_allowlist_active;
    predictedAllowlist = new Set(Array.isArray(all.predicted_domain_allowlist) ? all.predicted_domain_allowlist.map(String) : []);

    // per-domain payloads { policy, target_requests, ... }
    for (const [key, value] of Object.entries(all || {})) {
      if (!value) continue;
      if (value.policy) setPolicyForDomain(key, value.policy);
      if (Array.isArray(value.target_requests)) setDomainTargets(key, value.target_requests);
    }

    console.log("[bg] settings:",
      "disallow_untrusted_domains =", disallowUntrusted,
      "| predicted_allowlist_active =", predictedAllowlistActive,
      "| predicted_allowlist size =", predictedAllowlist.size
    );
  });
}

// ====== Listen for changes in storage and update in-memory structures ======

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;

  for (const [k, delta] of Object.entries(changes)) {
    // toggles
    if (k === "disallow_untrusted_domains") {
      disallowUntrusted = !!delta.newValue;
      console.log("[bg] changed: disallow_untrusted_domains =", disallowUntrusted);
      continue;
    }
    if (k === "predicted_domain_allowlist_active") {
      predictedAllowlistActive = !!delta.newValue;
      console.log("[bg] changed: predicted_allowlist_active =", predictedAllowlistActive);
      continue;
    }
    if (k === "predicted_domain_allowlist") {
      const arr = Array.isArray(delta.newValue) ? delta.newValue.map(String) : [];
      predictedAllowlist = new Set(arr);
      console.log("[bg] changed: predicted_allowlist size =", predictedAllowlist.size);
      continue;
    }

    // per-domain entries
    const val = delta.newValue;
    if (val === undefined) {
      // removed
      removeDomainTargets(k);
      removePolicyForDomain(k);
      continue;
    }
    if (val.policy) setPolicyForDomain(k, val.policy); else removePolicyForDomain(k);
    if (Array.isArray(val.target_requests)) setDomainTargets(k, val.target_requests); else removeDomainTargets(k);
  }
});

// ====== MATCHING =============================================================

function findTargetForRequest(hostname, method, url, parsedBody) {
  method = (method || "").toUpperCase();
  console.log("[bg] findTargetForRequest:", method, url);

  for (const [policyDomain, entries] of Object.entries(targetsByDomain)) {
    if (!domainMatches(policyDomain, hostname)) continue;

    for (const entry of entries) {
      if (entry.method && entry.method !== method) continue;
      if (!entry.regex.test(url)) continue;

      // If target requires body match, enforce it
      if (entry.bodyPattern && !deepContains(entry.bodyPattern, parsedBody || {})) {
        continue;
      }
      return entry; // matched method + url + (optional) body
    }
  }
  return null;
}

// Parse request body from details.requestBody (MV2, onBeforeRequest only)
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

// Deep "pattern is contained in target" matcher (objects & arrays)
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
//
// Order:
//   1) Predicted allowlist gate (if enabled)
//   2) Untrusted-domain gate (if enabled)
//   3) Target requests (deny / allow_public)
//

const pendingActionsByRequestId = new Map();

chrome.webRequest.onBeforeRequest.addListener(
  function onBeforeRequest(details) {
    // always allow extension's own requests
    if (isFromExtension(details)) {
      return {};
    }

    const destHostname = hostnameOf(details.url);
    const method = details.method;

    // -------- [1] Predicted allowlist gate (STRICT exact hostname) --------
    if (predictedAllowlistActive && details.url.startsWith("http")) {
      const currentDomain = tabTopDomains.get(details.tabId) || null;

      const inAllowlist = predictedAllowlist.has(destHostname); // strict: exact host match only
      const isSameAsCurrent = currentDomain && currentDomain === destHostname;
      // (optional guard to avoid self-bypass; keep if you added it earlier)
      const allowedByCurrentPolicy = !isSameAsCurrent && currentPolicyAllowsDest(currentDomain, destHostname);

      if (!inAllowlist && !allowedByCurrentPolicy) {
        console.log("[bg] DENY (predicted allowlist):", method, details.url,
                    "| current=", currentDomain || "<unknown>",
                    "| reason=not in allowlist and not allowed by current policy");

        // if this is a top-level navigation, redirect to our explainer page
        if (details.type === "main_frame") {
          const u = new URL(chrome.runtime.getURL("blocked.html"));
          // keep params short and safe for URLs
          u.searchParams.set("reason", "predicted_allowlist");
          u.searchParams.set("dest", destHostname);
          if (currentDomain) u.searchParams.set("current", currentDomain);
          // optional: show whether allowlist is on
          u.searchParams.set("active", String(predictedAllowlistActive));
          return { redirectUrl: u.toString() };
        }

        // otherwise (subresources), just cancel
        return { cancel: true };
      }
      // else pass to next gate
    }

    // update tabTopDomains on top-level navs
    if (details.type === "main_frame" && details.tabId >= 0 && destHostname) {
      tabTopDomains.set(details.tabId, destHostname);
    }

    // -------- [2] Untrusted-domain gate --------
    if (disallowUntrusted && details.url.startsWith("http")) {
      // Allow immediately if destination already has its own policy
      const destHasPolicy = !!policiesByDomain[destHostname];
      if (!destHasPolicy) {
        const currentDomain = tabTopDomains.get(details.tabId);

        // No current policy -> block
        if (!currentDomain || !policiesByDomain[currentDomain]) {
          console.log("[bg] DENY (untrusted: no current policy):", method, details.url,
                      "current=", currentDomain || "<unknown>");
          return { cancel: true };
        }

        // Current domain has a policy: only allow if dest ∈ allowed_domains
        if (!currentPolicyAllowsDest(currentDomain, destHostname)) {
          console.log("[bg] DENY (untrusted: dest not in current policy allowed_domains):",
                      method, details.url, "current=", currentDomain, "dest=", destHostname);
          return { cancel: true };
        }
        // else allowed to proceed
      }
      // if dest has its own policy, proceed
    }

    // -------- [3] Target matching (deny/allow_public) --------
    const bodyObj = parseRequestBody(details);
    const match = findTargetForRequest(destHostname, method, details.url, bodyObj);
    if (match) {
      if (match.decision === "deny") {
        console.log("[bg] DENY (target):", method, details.url, "matched", match.rawUrl);
        return { cancel: true };
      }
      if (match.decision === "allow_public") {
        pendingActionsByRequestId.set(details.requestId, "allow_public"); // strip cookie later
        return {};
      }
    }

    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestBody"]
);

// Strip Cookie header for "allow_public"
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
  ["blocking", "requestHeaders", "extraHeaders"] // extraHeaders needed for cookies
);

// Cleanup pending actions
const clearPending = (details) => pendingActionsByRequestId.delete(details.requestId);
chrome.webRequest.onCompleted.addListener(clearPending, { urls: ["<all_urls>"] });
chrome.webRequest.onErrorOccurred.addListener(clearPending, { urls: ["<all_urls>"] });
chrome.webRequest.onBeforeRedirect.addListener(clearPending, { urls: ["<all_urls>"] });

// ====== BOOTSTRAP ============================================================

loadAllFromStorage();
// all future actions are handled by onChanged listener
