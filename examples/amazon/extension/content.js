// -----------------------------------------------------------------------------
// Content script for PolicyRunner
// Responsibilities:
// 1. Monitor DOM element(s) specified by background
// 2. Capture latest DOM snapshots
// 3. Detect POST requests, form submissions, and submit button clicks
// 4. Send snapshot data to background for policy enforcement
// -----------------------------------------------------------------------------

console.log("[PolicyRunner] Content script loaded");
const latestValues = new Map();   // selector -> latest DOM value
const activeObservers = new Map(); // url_pattern -> selector -> MutationObserver

// -----------------------------------------------------------------------------
// Helper functions to manage observers
// -----------------------------------------------------------------------------
function registerObserver(urlPattern, selector, observer) {
  if (!activeObservers.has(urlPattern)) {
    activeObservers.set(urlPattern, new Map());
  }
  activeObservers.get(urlPattern).set(selector, observer);
}

function getObserver(urlPattern, selector) {
  return activeObservers.get(urlPattern)?.get(selector);
}

// TODO: Clear observers for SPAs when URL changes (popstate)
function clearObservers() {
  for (const [urlPattern, selectorMap] of activeObservers.entries()) {
    for (const [selector, observer] of selectorMap.entries()) {
      observer.disconnect();
    }
  }
  activeObservers.clear();
  latestValues.clear();
}

// -----------------------------------------------------------------------------
// Listen for setup messages from background script
// -----------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "DOM_MONITOR_SETUP" && Array.isArray(message.config)) {
    console.log("[PolicyRunner] Received DOM_MONITOR_SETUP", message.config);
    console.log("[PolicyRunner] Current URL:", window.location.href);
    console.log("Length of config:", message.config.length);

    const currentUrl = window.location.href;

    for (const entry of message.config) {
      const { url_matching, selector } = entry;
      console.log(`[PolicyRunner] Processing config entry`, entry);

      // Skip if not matching current page
      if (!matchesUrl(currentUrl, url_matching)) continue;
      console.log(`[PolicyRunner] URL ${currentUrl} matches pattern ${url_matching}`);

      // Skip duplicate observers
      if (getObserver(url_matching, selector)) continue;
      console.log(`[PolicyRunner] Setting up observer for selector ${selector} on URL pattern ${url_matching}`);

      watchElement(selector, url_matching);
    }

    sendResponse({ status: "ok" });
  }
  return true; // Keep the message channel open for async response
});

// -----------------------------------------------------------------------------
// Watch a DOM element for text changes, only if current URL matches pattern
// -----------------------------------------------------------------------------
function watchElement(selector, urlPattern = "*") {
  // Skip if current URL doesn’t match pattern
  console.debug(`[PolicyRunner] Setting up watch for selector: ${selector} on URL pattern: ${urlPattern}`);
  const currentUrl = window.location.href;
  if (!matchesUrl(currentUrl, urlPattern)) {
    console.debug(`[PolicyRunner] Skipping ${selector} — URL ${currentUrl} not matching ${urlPattern}`);
    return;
  }

  function startObserver(target) {
    const observer = new MutationObserver(() => {
      const value = target.textContent?.trim() ?? "";
      latestValues.set(selector, value);
      sendSnapshot("dom_change", urlPattern);
      console.debug(`[PolicyRunner] Detected change in ${selector}: ${value}`);
    });

    observer.observe(target, {
      attributes: true,
      childList: true,
      characterData: true,
      subtree: true,
    });

    registerObserver(urlPattern, selector, observer);

    // Initialize immediately with current value
    latestValues.set(selector, target.textContent?.trim() ?? "");
    sendSnapshot("dom_init", urlPattern);
    console.debug(`[PolicyRunner] Now observing selector: ${selector}, initial value: ${latestValues.get(selector)}`);
  }

  const el = document.querySelector(selector);
  if (el) {
    startObserver(el);
  } else {
    const bodyObserver = new MutationObserver(() => {
      const dynamicEl = document.querySelector(selector);
      if (dynamicEl) {
        bodyObserver.disconnect();
        startObserver(dynamicEl);
        clearTimeout(timeout); // stop the timeout once element found
      }
    });
    bodyObserver.observe(document.body, { childList: true, subtree: true });
    
    // Disconnect after 10s if element never appears
    const timeout = setTimeout(() => {
      bodyObserver.disconnect();
      console.debug(`[PolicyRunner] Timeout: stopped watching for selector ${selector}`);
    }, 10000);
  }
}

// -----------------------------------------------------------------------------
// URL pattern matching helper. Supports "*" wildcard.
// -----------------------------------------------------------------------------
function matchesUrl(url, pattern) {
  if (!pattern || pattern === "*") return true;
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*");
  const regex = new RegExp(`^${escaped}$`);
  return regex.test(url);
}

// -----------------------------------------------------------------------------
// Send current snapshot of all monitored elements to background
// -----------------------------------------------------------------------------
function sendSnapshot(reason, urlPattern = "*") {
  if (latestValues.size === 0) return;
  const snapshot = Object.fromEntries(latestValues.entries());
  chrome.runtime.sendMessage({
    type: "DOM_SNAPSHOT",
    domain: window.location.hostname,
    data: { [urlPattern]: snapshot },
    reason, // e.g., "form_submit" or "button_click"
  });
  console.debug(`[PolicyRunner] Sent DOM snapshot (${reason})`, snapshot);
}

// -----------------------------------------------------------------------------
// Detect user actions that likely trigger POST requests
// -----------------------------------------------------------------------------
// document.addEventListener("submit", () => sendSnapshot("form_submit"), true);

// document.addEventListener(
//   "click",
//   e => {
//     const el = e.target.closest("button, input[type=submit]");
//     if (el) sendSnapshot("button_click");
//   },
//   true
// );

// -----------------------------------------------------------------------------
// Optional: Intercept fetch POST requests
// -----------------------------------------------------------------------------
/*
const originalFetch = window.fetch;
window.fetch = async (...args) => {
  const response = await originalFetch(...args);
  if (args[1]?.method?.toUpperCase() === "POST") {
    sendSnapshot("fetch_post");
  }
  return response;
};
*/
