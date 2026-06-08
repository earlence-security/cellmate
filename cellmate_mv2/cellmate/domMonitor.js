// -----------------------------------------------------------------------------
// DOM Monitoring Module
// -----------------------------------------------------------------------------

// == Related globals defined in background.js ==

// argSpecMap: Map storing argument source/type specifications
// domain -> semantic_action -> arg_name -> { source, type }
// Example: argSpecMap.get("amazon.com").get("place_order").get("total_amount") = { source: {...}, type: "number" }

// snapshots: Map storing latest DOM snapshots from content scripts
// tabId -> { url -> { selector -> value } }
// Structure: Map -> Object -> Object
// Example: snapshots.get(tabId)[url][selector] = value

// -----------------------------------------------------------------------------
// Receive DOM value from content script and cache it
// Message format (from content): { type: "DOM_SNAPSHOT", selector, value }
// -----------------------------------------------------------------------------
/**
 * @param {number} tabId - Tab ID
 * @param {string} url_pattern - URL pattern of the page
 * @param {string} selector - DOM selector
 * @param {any} value - Captured DOM value
 * @param {Map} snapshots - Global snapshots map
 */
function cacheSnapshot(tabId, url_pattern, selector, value, snapshots) {
  if (!snapshots) {
    console.error("[DomMonitor] No snapshots map provided");
    return;
  }
  if (!tabId && tabId !== 0) return;
  let tabMap = snapshots.get(tabId);
  if (!tabMap) {
    tabMap = {};
    snapshots.set(tabId, tabMap);
  }
  if (!tabMap[url_pattern]) {
    tabMap[url_pattern] = {};
  }
  tabMap[url_pattern][selector] = value;
  console.log(
    `[DomMonitor] Cached snapshot for tab ${tabId} url ${url_pattern} selector ${selector}:`,
    value
  );
}

/**
 * Cache DOM snapshot data for a specific tab.
 * @param {number} tabId - Tab ID
 * @param {Object} data - Snapshot data
 * @param {Map} snapshots - Global snapshots map
 * @returns {void}
 */
function cacheSnapshotForTab(tabId, data, snapshots) {
  if (!snapshots) {
    console.error("[DomMonitor] No snapshots map provided");
    return;
  }
  // Initialize tab cache if missing
  if (!tabId && tabId !== 0) return;
  // data: { url_pattern -> { selector -> value } }
  for (const url_pattern in data) {
    for (const selector in data[url_pattern]) {
      cacheSnapshot(
        tabId,
        url_pattern,
        selector,
        data[url_pattern][selector],
        snapshots
      );
    }
  }
  console.log(`[DomMonitor] Cached snapshot for tab ${tabId}:`, data);
}

/** Allow content scripts to clear snapshots for a tab (optional)
 * @param {number} tabId - Tab ID
 * @param {Map} snapshots - Global snapshots map
 */
function clearSnapshotsForTab(tabId, snapshots) {
  if (!snapshots) {
    console.error("[DomMonitor] No snapshots map provided");
    return;
  }
  if (!tabId && tabId !== 0) return;
  snapshots.delete(tabId);
}

// Helper: Get cached snapshot for a tab and selector
function getCachedSnapshot(tabId, url, selector, snapshots) {
  if (!snapshots) {
    console.error("[DomMonitor] No snapshots map provided");
    return null;
  }
  const tabMap = snapshots.get(tabId);
  if (!tabMap) return null;
  const urlMap = tabMap[url];
  if (!urlMap) return null;
  const value = urlMap[selector];
  return value ?? null;
}

// -----------------------------------------------------------------------------
// Set up DOM monitoring for required arguments.
// -----------------------------------------------------------------------------

// Derives DOM monitor config directly from targetsByDomain (defined in background.js).
// targetsByDomain is in scope at call time since all background scripts share one global context.
function getDomMonitorConfigForDomain(domain) {
  const entries = targetsByDomain[domain] || [];
  const seen = new Set();
  const config = [];
  for (const entry of entries) {
    if (entry.decision !== "condition") continue;
    for (const spec of Object.values(entry.condition?.resolvedArgs || {})) {
      if (spec.source?.type === "dom") {
        const key = `${spec.source.url}||${spec.source.selector}`;
        if (!seen.has(key)) {
          seen.add(key);
          config.push({ url_pattern: spec.source.url, selector: spec.source.selector });
        }
      }
    }
  }
  return config.length > 0 ? config : null;
}

function getDomMonitorConfigForPage(domain, url) {
  const pageConfig = getDomMonitorConfigForDomain(domain);
  if (!pageConfig) return null;

  // Filter config for the specific page URL
  const filteredConfig = pageConfig.filter((entry) =>
    matchesUrl(url, entry.url_pattern)
  );
  return filteredConfig;
}

// -----------------------------------------------------------------------------
// URL pattern matching helper. Supports "*" wildcard.
// -----------------------------------------------------------------------------
function matchesUrl(url, pattern) {
  if (typeof url !== "string" || typeof pattern !== "string") return false;
  if (!pattern || pattern === "*") return true;
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\\/]/g, "\\$&")
    .replace(/\*/g, ".*");
  const regex = new RegExp(`^${escaped}$`);
  return regex.test(url);
}

// -----------------------------------------------------------------------------
// Enable dom monitoring on tab updates by sending DOM_MONITOR_SETUP messages
// to content scripts.
// -----------------------------------------------------------------------------
function startDomMonitoring(snapshots) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
      const url = new URL(tab.url);
      const domain = findPolicyDomain(url);
      const config = getDomMonitorConfigForPage(domain, tab.url);
      console.debug("[DomMonitor] Config:", config);
      if (config && config.length > 0) {
        console.log(
          `[DomMonitor] Sending monitor config to tab ${tabId}:`,
          config
        );
        chrome.tabs.sendMessage(tabId, {
          type: "DOM_MONITOR_SETUP",
          config: config,
        });
      }
      // TODO: Optionally clear snapshots on navigation
    }
  });

  // Find the policy domain key in targetsByDomain that matches this tab URL.
  // Checks full origin first (for webarena IP:port origins), then hostname suffix
  // (for real domains stored as bare hostnames like "amazon.com").
  function findPolicyDomain(url) {
    const origin = url.origin;
    const hostname = url.hostname;
    return Object.keys(targetsByDomain).find(key =>
      key === origin ||
      origin.endsWith("." + key) ||
      key === hostname ||
      hostname.endsWith("." + key)
    ) ?? origin;
  }

  // -----------------------------------------------------------------------------
  // Listen for content script messages (DOM_SNAPSHOT and optionally others)
  // -----------------------------------------------------------------------------
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || !msg.type) return;

    if (msg.type === "DOM_SNAPSHOT" && msg.data && msg.domain) {
      const tabId = sender.tab?.id;
      cacheSnapshotForTab(tabId, msg.data, snapshots);
      console.debug(`[DomMonitor] Updated snapshot cache:`, snapshots);
      if (sendResponse) sendResponse({ ok: true });
      return; // synchronous return allowed
    }

    if (msg.type === "CLEAR_SNAPSHOTS") {
      const tabId = sender.tab?.id;
      if (typeof tabId !== "undefined") clearSnapshotsForTab(tabId, snapshots);
      if (sendResponse) sendResponse({ ok: true });
      return;
    }

    if (msg.type === "ping") {
      console.log("[DomMonitor] ping from", sender.tab?.id);
      if (sendResponse) sendResponse({ ok: true });
      return;
    }
  });

  // Clean up snapshots when a tab is removed
  chrome.tabs.onRemoved.addListener((tabId) => {
    clearSnapshotsForTab(tabId, snapshots);
  });
}
