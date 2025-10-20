// -----------------------------------------------------------------------------
// Background script for PolicyRunner (MV2)
// - Loads WASM policies from extension folder (wasm/<domain>/<policy>.wasm)
// - Receives DOM snapshots from content scripts via DOM_SNAPSHOT messages
// - Can instruct tabs to start observing via DOM_MONITOR messages
// - Intercepts outgoing POST requests and runs policy using cached snapshot
// -----------------------------------------------------------------------------

// === Globals ===
let funcCache = new Map(); // function path -> implementation
let argConfig = new Map(); // domain -> semantic_action -> arg_name -> { source, type }
let domMonitorConfig = new Map(); // domain -> [ { url_matching, selector } ]
const enc = new TextEncoder();
const dec = new TextDecoder();

// Cache latest DOM snapshots sent from content scripts
// Structure: snapshots.get(tabId) -> Map(url -> Map(selector -> { value, ts }))
const snapshots = new Map();

// -----------------------------------------------------------------------------
// Helper: Construct function path from domain and function name
// -----------------------------------------------------------------------------
function constructFunctionPath(domain, functionName) {
  return `functions/${domain}/${functionName}.js`;
}

// -----------------------------------------------------------------------------
// Pre-load and cache functions.
// -----------------------------------------------------------------------------
async function preloadFunctions(functionPaths) {
  for (const funcPath of functionPaths) {
    if (funcCache.has(funcPath)) continue;
    try {
      console.log(`[PolicyRunner] Loading function module from ${funcPath}`);
      const module = await import(chrome.runtime.getURL(funcPath));
      funcCache.set(funcPath, module.default);
      console.log(`[PolicyRunner] Loaded function module from ${funcPath}`);
    } catch (err) {
      console.error(`[PolicyRunner] Failed to load function module from ${funcPath}:`, err);
    }
  }
}

// -----------------------------------------------------------------------------
// Execute a function in imported JS.
// -----------------------------------------------------------------------------
function executeFunction(domain, functionDetails, inputObj, fallbackDefault = false) {
  try {
    const funcPath = constructFunctionPath(domain, functionDetails.name);
    const func = funcCache.get(funcPath);
    if (!func) {
      console.error(`[PolicyRunner] No function loaded for path ${funcPath}`);
      return fallbackDefault;
    }
    const parameterObj = functionDetails.parameters || {};
    console.log(`[PolicyRunner] Executing function ${functionDetails.name} with parameters:`, parameterObj, "and input:", inputObj);

    return func(parameterObj, inputObj);
  } catch (err) {
    console.error("[PolicyRunner] Policy execution error:", err);
    return fallbackDefault;
  }
}

// -----------------------------------------------------------------------------
// Receive DOM value from content script and cache it
// Message format (from content): { type: "DOM_SNAPSHOT", selector, value }
// -----------------------------------------------------------------------------
function cacheSnapshot(tabId, url_pattern, selector, value) {
  if (!tabId && tabId !== 0) return;
  let tabMap = snapshots.get(tabId);
  if (!tabMap) {
    tabMap = new Map();
    snapshots.set(tabId, tabMap);
  }
  let urlMap = tabMap.get(url_pattern);
  if (!urlMap) {
    urlMap = new Map();
    tabMap.set(url_pattern, urlMap);
  }
  urlMap.set(selector, { value, ts: Date.now() });
  console.log(`[PolicyRunner] Cached snapshot for tab ${tabId} url ${url_pattern} selector ${selector}:`, value);
}

function cacheSnapshotForTab(tabId, data) {
    // Initialize tab cache if missing
    if (!tabId && tabId !== 0) return;
    let tabMap = snapshots.get(tabId);
    snapshots.set(tabId, data);

    console.log(`[PolicyRunner] Cached snapshot for tab ${tabId}:`, data);
}

// Allow content scripts to clear snapshots for a tab (optional)
function clearSnapshotsForTab(tabId) {
  snapshots.delete(tabId);
}

// Helper: Get cached snapshot for a tab and selector
function getCachedSnapshot(tabId, url, selector) {
  const tabMap = snapshots.get(tabId);
  if (!tabMap) return null;
  const urlMap = tabMap[url];
  if (!urlMap) return null;
  const value = urlMap[selector];
  return value ?? null;
}

// -----------------------------------------------------------------------------
// Fallback: fetch DOM value directly from tab if no cached snapshot
// This approach won't work if the page where monitored dom element lives is unloaded.
// -----------------------------------------------------------------------------
async function fetchDomValueFromTab(tabId, selector, timeout = 8000) {
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId },
      func: (sel, timeMs) =>
        new Promise((resolve) => {
          const start = Date.now();
          const check = () => {
            const el = document.querySelector(sel);
            if (el) return resolve(el.innerText.trim());
            if (Date.now() - start > timeMs) return resolve(null);
            setTimeout(check, 150);
          };
          check();
        }),
      args: [selector, timeout],
    });
    return result?.result || null;
  } catch (e) {
    console.warn(`[PolicyRunner] Failed to read DOM from tab ${tabId}:`, e);
    return null;
  }
}

// -----------------------------------------------------------------------------
// Retrieve argument configurations from sitemap and cache them.
// -----------------------------------------------------------------------------
function retrieveArgConfigs(policy, sitemap, domain) {
  for (const argName of policy.condition.args || []) {
    const argSpec = sitemap.find((item) => item.semantic_action === policy.action)?.args?.[argName];
    if (argSpec) {
      // domain -> semantic_action -> arg_name -> { source, type }
      let domainConfig = argConfig.get(domain);
      if (!domainConfig) {
        domainConfig = new Map();
        argConfig.set(domain, domainConfig);
      }
      let semanticActionConfig = domainConfig.get(policy.action);
      if (!semanticActionConfig) {
        semanticActionConfig = new Map();
        domainConfig.set(policy.action, semanticActionConfig);
      }
      semanticActionConfig.set(argName, {
        source: argSpec.source,
        type: argSpec.type,
      });
      console.log(`[PolicyRunner] Retrieved arg config`, argConfig);
    }
  }
}

// -----------------------------------------------------------------------------
// Set up DOM monitoring for required arguments.
// -----------------------------------------------------------------------------
function setupDomMonitoring(policy, sitemap, domain) {
  if (!policy || !policy.condition || !sitemap) {
    console.error("[PolicyRunner] Invalid policy or sitemap for building args to monitor");
    return;
  }
  for (const argName of policy.condition.args || []) {
    // Only consider args sourced from DOM and necessary for policy
    console.log(`[PolicyRunner] Setting up DOM monitoring for arg: ${argName}`);
    const argSpec = argConfig.get(domain)?.get(policy.action)?.get(argName);
    console.log(`[PolicyRunner] Arg spec for ${argName}:`, argSpec);
    if (argSpec && argSpec.source && argSpec.source.type === "dom") {
      let config = domMonitorConfig.get(domain);
      if (!config) {
        config = [];
        domMonitorConfig.set(domain, config);
      }
      config.push({ url_matching: argSpec.source.url, selector: argSpec.source.selector });
      console.log(`[PolicyRunner] Created/Updated DOM monitor config for domain: ${domain}, config:`, config);
    }
  }
}

// -----------------------------------------------------------------------------
// Based on the compiled policy (i.e., Map<Request, Accept/Deny/Wasm>),
// Decide which action to take for an intercepted request.
// -----------------------------------------------------------------------------
function getPolicyResultForUrl(url) {
  // TODO: Replace with real policy lookup logic
  return { type: "function", domain: "amazon.com", details: policy["condition"]};
}

// -----------------------------------------------------------------------------
// Get arguments for the Wasm Policy. Input could comes from:
//  - details of the intercepted request
//  - cached DOM snapshot (preferred)
//  - live DOM read (fallback, optional)
// -----------------------------------------------------------------------------
function buildInputForFunction(policy, req_details, domain) {
  const functionArgs = {};
  console.log("[PolicyRunner] Building input for args:", policy.condition.args);
  for (const argName of policy.condition?.args || []) {
    console.log(`[PolicyRunner] Building input for arg ${argName}`);
    const argSpec = argConfig.get(domain)?.get(policy.action)?.get(argName);
    if (!argSpec) {
      console.warn(`[PolicyRunner] No arg spec found for arg ${argName}`);
      continue;
    }
    const source = argSpec.source || {};
    if (source.type === "dom" && source.selector) {
      // Identify of the monitored dom element
      const tabId = req_details.tabId;
      const url = source.url;   // This is url pattern from the policy, not the actual url
      const selector = source.selector;
      // Fetch the DOM value from cached snapshot
      const domValue = getCachedSnapshot(tabId, url, selector);
      if (domValue === null) {
        console.error(`[PolicyRunner] No cached snapshot for tab ${tabId} url ${url} selector ${selector}`);
      }
      functionArgs[argName] = domValue;
    } else {
      console.warn(`[PolicyRunner] Unsupported arg source type: ${source.type}`);
    }
    // Process type conversions
    if (argSpec.type === "number") {
      const parsedValue = parseFloat((functionArgs[argName] + "").replace(/[^0-9.-]+/g, ""));
      if (isNaN(parsedValue)) {
        console.error(`[PolicyRunner] Failed to parse number for arg ${argName}:`, functionArgs[argName]);
      }
      functionArgs[argName] = parsedValue;
    }
  }
  console.log("[PolicyRunner] Built function args:", functionArgs);
  return functionArgs;
}

// -----------------------------------------------------------------------------
// Preload policies at startup (optional). Add any policies you want ready.
// -----------------------------------------------------------------------------
const domain = "amazon.com";
const policy = {
    "effect": "allow",
    "action": "place_order",
    "condition": {
        "name": "amazon_allow_purchase_if_amount_leq",
        "args": [
            "total_amount"
        ],
        "parameters": {
            "max_amount": 1
        }
    },
    "description": "Allow purchase if total amount is less than or equal to $1"
};

const sitemap = [
    {
        "semantic_action": "buy_now",
        "description": "Buy an item now",
        "url": "https://www.amazon.com/checkout/entry/buynow",
        "method": "POST",
    },
    {
        "semantic_action": "view_shopping_cart",
        "description": "View shopping cart",
        "url": "https://www.amazon.com/gp/cart/view.html*",
        "method": "GET",
    },
    {
        "semantic_action": "checkout_shopping_cart",
        "description": "Checkout shopping cart",
        "url": "https://www.amazon.com/checkout/entry/cart*",
        "method": "GET",
    },
    {
        "semantic_action": "place_order",
        "description": "Place an order",
        "url": "https://www.amazon.com/checkout/p/*/spc/place-order*",
        "method": "POST",
        "args": {
            "total_amount": {
                "type": "number",
                "source": {
                    "type": "dom",
                    "url": "https://www.amazon.com/checkout/p/*",
                    "selector": "#subtotals-marketplace-table li:nth-child(4) .order-summary-line-definition"
                }
            }
        }
    }
];

// Preload policies at startup. Currently the first policy wasm will be loaded.
// TODO: Iterate over all policies for each domain.
const functionInfo = policy?.condition || {}
const functionName = functionInfo?.name || "";
if (!domain || !functionName) {
  console.error("No domain or function name specified for preloading");
}
const functionPath = constructFunctionPath(domain, functionName);
console.log(`[PolicyRunner] Preloading function for ${domain}/${functionName} from ${functionPath}`);

// Pre-load and cache function modules
preloadFunctions([functionPath]);


// Preprocess arguments and add config.
retrieveArgConfigs(policy, sitemap, domain);


// Setup dom monitoring config for amazon.com
setupDomMonitoring(policy, sitemap, domain);

// -----------------------------------------------------------------------------
// Enable dom monitoring on tab updates by sending DOM_MONITOR_SETUP messages
// to content scripts.
// -----------------------------------------------------------------------------
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    const url = new URL(tab.url);
    const config = domMonitorConfig.get(url.hostname.replace(/^www\./, "")) ||
                   domMonitorConfig.get(url.hostname);
    console.log(`[PolicyRunner] Tab ${tabId} updated. Sending DOM_MONITOR_SETUP if config exists.`);
    console.debug("Config:", domMonitorConfig);
    console.debug("hostname:", url.hostname.replace(/^www\./, ""));
    if (config) {
      console.log(`Sending monitor config to tab ${tabId}:`, config);
      chrome.tabs.sendMessage(tabId, { type: "DOM_MONITOR_SETUP", config: config });
    }
  }
});

// -----------------------------------------------------------------------------
// Listen for content script messages (DOM_SNAPSHOT and optionally others)
// -----------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return;

  if (msg.type === "DOM_SNAPSHOT" && msg.data && msg.domain) {
    const tabId = sender.tab?.id;
    cacheSnapshotForTab(tabId, msg.data);

    console.debug(`[PolicyRunner] Updated snapshot cache:`, snapshots);
    // TODO: Replace selector with the function::variable if needed
    // Optionally ack
    if (sendResponse) sendResponse({ ok: true });
    return; // synchronous return allowed
  }

  if (msg.type === "CLEAR_SNAPSHOTS") {
    const tabId = sender.tab?.id;
    if (typeof tabId !== "undefined") clearSnapshotsForTab(tabId);
    if (sendResponse) sendResponse({ ok: true });
    return;
  }

  if (msg.type === "ping") {
    console.log("[PolicyRunner] ping from", sender.tab?.id);
    if (sendResponse) sendResponse({ ok: true });
    return;
  }
});

// Clean up snapshots when a tab is removed
chrome.tabs.onRemoved.addListener((tabId) => {
  clearSnapshotsForTab(tabId);
});

// -----------------------------------------------------------------------------
// Intercept outgoing requests and run policy
// -----------------------------------------------------------------------------
chrome.webRequest.onBeforeRequest.addListener(
  function (details) {
    // Only handle top-level navigations / POSTs (customize as needed)
    if (!details || !details.url) return {};

    // Example request: POST www.amazon.com/checkout/p/*/spc/place-order*
    // TODO: should remove this for production; just for testing
    if (details.method !== "POST") return {};

    const result = getPolicyResultForUrl(details.url, details.method);
    console.debug("[PolicyRunner] Policy result:", result);

    // Handle simple allow/deny policies
    if (result.type === "allow") {
      return {};
    }
    if (result.type === "deny") {
      return { cancel: true };
    }
    // Handle function-based policies
    if (!result || result.type !== "function") {
      console.error("Invalid policy result");
      return { cancel: true };
    }
    const functionDetails = result.details;
    if (!functionDetails || !functionDetails.name || !functionDetails.args || !functionDetails.parameters) return {};
    const input = buildInputForFunction(policy, details, domain);
    console.log("[PolicyRunner] Policy input:", input);

    const allowed = executeFunction(domain, functionDetails, input); // default deny on errors
    console.log(`[PolicyRunner] Policy ${functionDetails.name} decision: ${allowed ? "ALLOW" : "DENY"}`);

    if (!allowed) {
      // Deny immediately (if you want to combine multiple policies,
      // change logic here to aggregate decisions)
      return { cancel: true };
    }

    // If all policies (if any) allowed the request, permit it
    return {};
  },
  {
    urls: ["https://www.amazon.com/checkout/p/*/spc/place-order*"], // tune to your endpoints
  },
  ["blocking", "requestBody"]
);
