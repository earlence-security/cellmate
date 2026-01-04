// -----------------------------------------------------------------------------
// Background script for PolicyRunner (MV2)
// - Loads WASM policies from extension folder (wasm/<domain>/<policy>.wasm)
// - Receives DOM snapshots from content scripts via DOM_SNAPSHOT messages
// - Can instruct tabs to start observing via DOM_MONITOR messages
// - Intercepts outgoing POST requests and runs policy using cached snapshot
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Define global caches
// -----------------------------------------------------------------------------

// == For function execution ==
// Store argument source/type specifications
// domain -> semantic_action -> arg_name -> { source, type }
// Example: argSpecMap.get("amazon.com").get("place_order").get("total_amount") = { source: {...}, type: "number" }
self.argSpecMap = self.argSpecMap || new Map();

// Cache loaded function implementations
// function path -> implementation
// Example: funcCache.get("amazon.com/amazon_allow_purchase_if_amount_leq") = function(...) { ... }
self.funcCache = self.funcCache || new Map(); // function path -> implementation

// == For DOM monitoring ==
// Cache latest DOM snapshots sent from content scripts
// tabId -> { url -> { selector -> { value, ts } } }
// Structure: Map -> Object -> Object
// Example: snapshots.get(tabId)[url][selector] = { value: "...", ts: 1234567890 }
self.snapshots = self.snapshots || new Map();

// -----------------------------------------------------------------------------
// Load helper scripts
// -----------------------------------------------------------------------------
// importScripts("argSpec.js", "./domMonitor.js", "./functionExecutor.js");

// -----------------------------------------------------------------------------
// Define policy, sitemap, and domain
// -----------------------------------------------------------------------------
const domain = "amazon.com";

const rule_shopping_cart = {
  effect: "condition",
  action: "checkout_shopping_cart",
  condition: {
    name: "amazon_allow_checkout_if_amount_leq",
    args: ["cart_total_amount"],
    parameters: {
      max_amount: 0.9,
    },
  },
  description:
    "Allow checkout if cart total amount is less than or equal to $0.90",
};

const rule_checkout = {
  effect: "condition",
  action: "place_order",
  condition: {
    name: "amazon_allow_purchase_if_amount_leq",
    args: ["total_amount"],
    parameters: {
      max_amount: 1,
    },
  },
  description: "Allow purchase if total amount is less than or equal to $1",
};

const policy = {
  domain: domain,
  rules: [rule_checkout, rule_shopping_cart],
};

const sitemap = [
  {
    semantic_action: "buy_now",
    description: "Buy an item now",
    url: "https://www.amazon.com/checkout/entry/buynow",
    method: "POST",
  },
  {
    semantic_action: "view_shopping_cart",
    description: "View shopping cart",
    url: "https://www.amazon.com/gp/cart/view.html*",
    method: "GET",
  },
  {
    semantic_action: "checkout_shopping_cart",
    description: "Checkout shopping cart",
    url: "https://www.amazon.com/checkout/entry/cart*",
    method: "GET",
    args: {
      cart_total_amount: {
        type: "number",
        source: {
          type: "dom",
          url: "https://www.amazon.com/*cart*",
          selector: "#sc-subtotal-amount-buybox > span",
        },
      },
    },
  },
  {
    semantic_action: "place_order",
    description: "Place an order",
    url: "https://www.amazon.com/checkout/p/*/spc/place-order*",
    method: "POST",
    args: {
      total_amount: {
        type: "number",
        source: {
          type: "dom",
          url: "https://www.amazon.com/checkout/p/*",
          selector:
            "#subtotals-marketplace-table li:nth-child(4) .order-summary-line-definition",
        },
      },
    },
  },
];

// -----------------------------------------------------------------------------
// Preload function modules
// -----------------------------------------------------------------------------
setupFunctionExecution(
  policy,
  sitemap,
  domain,
  self.argSpecMap,
  self.funcCache
);

// -----------------------------------------------------------------------------
// Setup DOM monitoring for the domain based on policy and sitemap
// -----------------------------------------------------------------------------
startDomMonitoring(self.argSpecMap, self.snapshots);

// -----------------------------------------------------------------------------
// Intercept outgoing requests and run policy
// -----------------------------------------------------------------------------
chrome.webRequest.onBeforeRequest.addListener(
  function (reqDetails) {
    try {
      const result = getPolicyResultForUrl(
        policy,
        reqDetails.url,
        reqDetails.method
      );
      console.debug("[PolicyRunner] Policy result:", result);

      // Handle simple allow/deny policies
      if (result.effect === "allow") {
        return {};
      }
      if (result.effect === "deny") {
        return { cancel: true };
      }
      // Handle function-based policies
      if (!result || result.effect !== "condition") {
        console.error("Invalid policy result");
        return { cancel: true };
      }
      const semanticAction = result.action;
      const funcDetails = result.condition;
      if (
        !semanticAction ||
        !funcDetails ||
        !funcDetails.name ||
        !funcDetails.args ||
        !funcDetails.parameters
      ) {
        console.error("Invalid function details in policy result");
        return { cancel: true };
      }
      const input = buildInputForFunction(
        semanticAction,
        funcDetails,
        reqDetails,
        domain,
        self.argSpecMap,
        self.snapshots,
        getCachedSnapshot
      );
      console.log("[PolicyRunner] Policy input:", input);

      const allowed = executeFunction(
        domain,
        funcDetails,
        input,
        self.funcCache
      ); // default deny on errors
      console.log(
        `[PolicyRunner] Policy ${funcDetails.name} decision: ${
          allowed ? "ALLOW" : "DENY"
        }`
      );

      // if (!allowed) {
      // Deny immediately (if you want to combine multiple policies,
      // change logic here to aggregate decisions)
      return { cancel: true };
      // }

      // If all policies (if any) allowed the request, permit it
      return {};
    } catch (err) {
      // On error, deny the request for safety
      console.error("[PolicyRunner] Error during request interception:", err);
      return { cancel: true };
    }
  },
  {
    urls: [
      "https://www.amazon.com/checkout/p/*/spc/place-order*",
      "https://www.amazon.com/checkout/entry/cart*",
    ], // tune to your endpoints
  },
  ["blocking", "requestBody"]
);
