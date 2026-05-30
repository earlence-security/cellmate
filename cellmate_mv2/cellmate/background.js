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

// ====== Load resources from storage during startup ======

function loadAllFromStorage() {
  chrome.storage.local.get(null, (all) => {
    if (chrome.runtime.lastError) {
      console.warn("[bg] storage load error:", chrome.runtime.lastError);
      return;
    }

    // per-domain payloads { policy, target_requests, ... }
    for (const [key, value] of Object.entries(all || {})) {
      if (!value) continue;
      if (Array.isArray(value.target_requests)) setDomainTargets(key, value.target_requests);
    }

    console.log("[bg] loaded target policies for", Object.keys(targetsByDomain).length, "domain(s)");
  });
}

// ====== Listen for changes in storage and update in-memory structures ======

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;

  for (const [k, delta] of Object.entries(changes)) {
    // per-domain entries
    const val = delta.newValue;
    if (val === undefined) {
      removeDomainTargets(k);
      continue;
    }
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
// Selected setup policies compile to target_requests. Requests matching a saved
// deny target are blocked; requests matching allow_public have Cookie stripped.
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
