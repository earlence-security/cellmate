
// ====== CONFIG / HELPERS =====================================================

const EXT_ORIGIN = `chrome-extension://${chrome.runtime.id}`;

// Turn a template URL (supports {param} and *) into a RegExp
//   - {param}  -> matches one path segment ([^/]+) i.e. https://gitlab.com/{group}/{project}/-/project_members/{user_id}
//   - *        -> matches anything (.*) i.e. https://gitlab.com/api/v4/projects/{project_id}/repository/commits*
// Everything else is literally matched (we escape regex metacharacters).
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
    details.originUrl === EXT_ORIGIN ||          // older Chromium used originUrl
    (details.tabId === -1 && details.initiator?.startsWith("chrome-extension://"))
  );
}




// ====== DATA STRUCTS AND RELATED FUNCTIONS ======================================================

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


// ====== For storing target urls to apply enforcement per domain =======

// targetsByDomain = {
//   "gitlab.com": [
//     { method: "POST", rawUrl: "https://gitlab.com/.../{id}/*", regex: /.../, decision: "deny" },
//     ...
//   ],
//   ...
// }
//
// This is kept in sync with chrome.storage.local via onChanged.
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
// (currently only used to figure out which domains are explicitely allowed via policy)

// Setup for policies (kept in sync with chrome.storage.local via onChanged)
// policiesByDomain = {
//   "example.com": {...},
//   ...
// }
const policiesByDomain = Object.create(null);

function setPolicyForDomain(domain, policyObj) {
  const allowed = new Set((policyObj?.allowed_domains || []).map(String));
  policiesByDomain[domain] = { allowedDomains: allowed, hasPolicy: true };
}

function removePolicyForDomain(domain) {
  delete policiesByDomain[domain];
}


// ====== Load resrouces from storage during startup ======

// Initial load of settings and policies + targets per domain
function loadAllFromStorage() {
  chrome.storage.local.get(null, (all) => {
    if (chrome.runtime.lastError) {
      console.warn("[bg] storage load error:", chrome.runtime.lastError);
      return;
    }

    // toggle
    if (typeof all.disallow_untrusted_domains === "boolean") {
      disallowUntrusted = all.disallow_untrusted_domains;
    } else {
      chrome.storage.local.set({ disallow_untrusted_domains: true });
      disallowUntrusted = true;
    }

    // per-domain payloads { policy, target_requests, ... }
    for (const [key, value] of Object.entries(all || {})) {
      if (!value) continue;
      if (value.policy) setPolicyForDomain(key, value.policy);
      if (Array.isArray(value.target_requests)) setDomainTargets(key, value.target_requests);
    }
    console.log("[bg] settings: disallow_untrusted_domains =", disallowUntrusted);
  });
}


// ====== Listen for changes in storage and update in-memory structures ======

// Listen for changes (new/updated policies per domain)
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  for (const [k, delta] of Object.entries(changes)) {
    if (k === "disallow_untrusted_domains") {
      disallowUntrusted = !!delta.newValue;
      console.log("[bg] setting changed: disallow_untrusted_domains =", disallowUntrusted);
      continue;
    }
    // Domain entries
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

// Find a matching target for a given request (hostname+method+url) by iterating through targetsByDomain
function findTargetForRequest(hostname, method, url, parsedBody) {
  method = (method || "").toUpperCase();

  for (const [policyDomain, entries] of Object.entries(targetsByDomain)) {
    if (!domainMatches(policyDomain, hostname)) continue;

    for (const entry of entries) {
      if (entry.method && entry.method !== method) continue;
      if (!entry.regex.test(url)) continue;

      // New: if target requires body match, enforce it
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

  // If Chrome parsed form data for us
  if (rb.formData) {
    // formData is { key: [values...] } — convert to { key: value or [values] }
    const obj = {};
    for (const [k, arr] of Object.entries(rb.formData)) {
      obj[k] = arr.length === 1 ? arr[0] : arr.slice();
    }
    return obj;
  }

  // Otherwise raw bytes (ArrayBuffer); try to decode and parse JSON
  if (rb.raw && rb.raw.length > 0 && rb.raw[0].bytes) {
    try {
      const dec = new TextDecoder("utf-8");
      const str = dec.decode(new Uint8Array(rb.raw[0].bytes));
      // Try JSON first
      try {
        return JSON.parse(str);
      } catch {
        // Fallback: x-www-form-urlencoded string "a=1&b=2"
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
        // Unknown format; keep raw string
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
  if (pattern === null || pattern === undefined) return true; // nothing to check
  if (target === null || target === undefined) return false;

  // primitives
  const isObj = v => typeof v === "object" && v !== null;
  if (!isObj(pattern)) return Object.is(pattern, target);

  // arrays
  if (Array.isArray(pattern)) {
    if (!Array.isArray(target)) return false;
    // every item in pattern must appear in target (shallow compare or stringify fallback)
    return pattern.every(pItem =>
      target.some(tItem =>
        (isObj(pItem) || isObj(tItem))
          ? JSON.stringify(pItem) === JSON.stringify(tItem)
          : Object.is(pItem, tItem)
      )
    );
  }

  // objects
  if (!isObj(target)) return false;
  for (const [k, v] of Object.entries(pattern)) {
    if (!(k in target)) return false;
    if (!deepContains(v, target[k])) return false;
  }
  return true;
}




// ====== ENFORCEMENT ==========================================================
//
// MV2 requires "webRequest" + "webRequestBlocking" permissions.
// We split enforcement in two steps:
//   - onBeforeRequest: cancel when decision === "deny", mark when decision === "allow_public"
//   - onBeforeSendHeaders: strip Cookie from marked requests
//     (this keeps the request but removes cookies from header)
//

// mark requestIds that need Cookie stripping
const pendingActionsByRequestId = new Map();

// Cancel or record decision based on matching results between targets and the current request
chrome.webRequest.onBeforeRequest.addListener(
  function onBeforeRequest(details) {
    // always allow extension's own requests
    if (isFromExtension(details)) {
      return {};
    }

    const destHostname = hostnameOf(details.url);
    const method = details.method;

    // update tabTopDomains on top-level navs
    if (details.type === "main_frame" && details.tabId >= 0 && destHostname) {
      tabTopDomains.set(details.tabId, destHostname);
    }

    // --- 1) UNTRUSTED-DOMAIN CHECK FIRST ---
    // Block requests to domains without a policy, unless explictly allowed by current domain's policy
    if (disallowUntrusted && details.url.startsWith("http")) {
      // Allow immediately if destination already has its own policy
      const destHasPolicy = !!policiesByDomain[destHostname];
      if (!destHasPolicy) {
        const currentDomain = tabTopDomains.get(details.tabId);

        // No current domain or no policy for it -> block
        if (!currentDomain || !policiesByDomain[currentDomain]) {
          console.log("[bg] DENY (untrusted-first: no current policy):", method, details.url,
                      "current=", currentDomain || "<unknown>");
          return { cancel: true };
        }

        // Current domain has a policy: only allow if dest ∈ allowed_domains
        const allowedSet = policiesByDomain[currentDomain].allowedDomains;
        const allowed = Array.from(allowedSet).some(ad => domainMatches(ad, destHostname));
        if (!allowed) {
          console.log("[bg] DENY (untrusted-first: dest not allowed):", method, details.url,
                      "current=", currentDomain, "dest=", destHostname);
          return { cancel: true };
        }
        // else allowed to proceed to target matching
      }
      // if dest has policy, proceed to target matching
    }

    // --- 2) TARGET REQUESTS (deny / allow_public) ---
    // Check if request matches any target. if so, enforce decision accordingly
    const bodyObj = parseRequestBody(details);
    const match = findTargetForRequest(destHostname, method, details.url, bodyObj);
    if (match) {
      if (match.decision === "deny") {
        console.log("[bg] DENY (target):", method, details.url, "matched", match.rawUrl);
        return { cancel: true };
      }
      if (match.decision === "allow_public") {
        pendingActionsByRequestId.set(details.requestId, "allow_public"); // strip cookie during onBeforeSendHeaders
        return {};
      }
    }

    // no action needed
    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestBody"]
);

// Actually strip Cookie header for those we marked earlier
chrome.webRequest.onBeforeSendHeaders.addListener(
  function onBeforeSendHeaders(details) {
    // No modification if not marked or from extension
    if (isFromExtension(details) || pendingActionsByRequestId.get(details.requestId) !== "allow_public") {
      return { requestHeaders: details.requestHeaders };
    }

    // Remove Cookie headers
    const filtered = (details.requestHeaders || []).filter(
      (h) => h.name.toLowerCase() !== "cookie"
    );

    console.log("[bg] Stripped Cookie for", details.method, details.url);
    return { requestHeaders: filtered };
  },
  { urls: ["<all_urls>"] },
  // extraHeaders needed for cookies
  ["blocking", "requestHeaders", "extraHeaders"] 
);

// Cleanup pendingActionsByRequestId when requests complete, error out, or redirect
const clearPending = (details) => pendingActionsByRequestId.delete(details.requestId);
chrome.webRequest.onCompleted.addListener(clearPending, { urls: ["<all_urls>"] });
chrome.webRequest.onErrorOccurred.addListener(clearPending, { urls: ["<all_urls>"] });
chrome.webRequest.onBeforeRedirect.addListener(clearPending, { urls: ["<all_urls>"] });




// ====== BOOTSTRAP ============================================================

loadAllFromStorage();
// all future actions are handled by onChanged listener
