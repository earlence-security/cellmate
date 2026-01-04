// -----------------------------------------------------------------------------
// Helper Functions for Function Execution and Argument Building
// -----------------------------------------------------------------------------

// == Related globals defined in background.js ==

// argSpecMap: Map storing argument source/type specifications
// domain -> semantic_action -> arg_name -> { source, type }
// Example: argSpecMap.get("amazon.com").get("place_order").get("total_amount") = { source: {...}, type: "number" }

// funcCache: Map storing loaded function implementations
// function path -> implementation
// Example: funcCache.get("amazon.com/amazon_allow_purchase_if_amount_leq") = function(...){...}

// -----------------------------------------------------------------------------
// Pre-load and cache functions.
// -----------------------------------------------------------------------------
async function preloadSingleFunction(functionPath) {
  if (!functionPath) return null;
  try {
    console.log(
      `[FunctionExecutor] Loading function module from ${functionPath}`
    );
    const module = await import(chrome.runtime.getURL(functionPath));
    console.log(
      `[FunctionExecutor] Loaded function module from ${functionPath}`
    );
    return module.default;
  } catch (err) {
    console.error(
      `[FunctionExecutor] Failed to load function module from ${functionPath}:`,
      err
    );
    return null;
  }
}

async function preloadFunctions(functionPaths, funcCache = null) {
  if (!funcCache) {
    console.error("[FunctionExecutor] funcCache must be provided");
    return;
  }
  for (const funcPath of functionPaths) {
    if (!funcPath || funcCache.has(funcPath)) continue;
    const func = await preloadSingleFunction(funcPath);
    if (func) {
      funcCache.set(funcPath, func);
    }
  }
  return funcCache;
}

// -----------------------------------------------------------------------------
// Data Structure: Argument Specification
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Get arguments for the Wasm Policy. Input could comes from:
//  - details of the intercepted request
//  - cached DOM snapshot (preferred)
//  - live DOM read (fallback, optional)
// -----------------------------------------------------------------------------
function buildInputForFunction(
  semanticAction,
  funcDetails,
  reqDetails,
  domain,
  argSpecMap,
  snapshots = null,
  snapshotGetter = null
) {
  const functionArgs = {};
  console.log("[FunctionExecutor] Building input for args:", funcDetails.args);
  for (const argName of funcDetails.args || []) {
    console.log(`[FunctionExecutor] Building input for arg ${argName}`);
    const argSpec = lookupArgSpec(domain, semanticAction, argName, argSpecMap);
    if (!argSpec) {
      console.warn(`[FunctionExecutor] No arg spec found for arg ${argName}`);
      continue;
    }
    const source = argSpec.source || {};
    if (source.type === "dom" && source.selector) {
      // Identify of the monitored dom element
      const tabId = reqDetails.tabId;
      const url = source.url; // This is url pattern from the policy, not the actual url
      const selector = source.selector;
      // Fetch the DOM value from cached snapshot
      if (!snapshots) {
        console.error(
          `[FunctionExecutor] No snapshots cache provided for fetching DOM value for arg ${argName}`
        );
      }
      const domValue = snapshotGetter
        ? snapshotGetter(tabId, url, selector, snapshots)
        : null;
      if (domValue === null) {
        console.error(
          `[FunctionExecutor] No cached snapshot for tab ${tabId} url ${url} selector ${selector}`
        );
      }
      functionArgs[argName] = domValue;
    } else {
      console.warn(
        `[FunctionExecutor] Unsupported arg source type: ${source.type}`
      );
    }
    // Process type conversions
    if (argSpec.type === "number") {
      const parsedValue = parseFloat(
        (functionArgs[argName] + "").replace(/[^0-9.-]+/g, "")
      );
      if (isNaN(parsedValue)) {
        console.error(
          `[FunctionExecutor] Failed to parse number for arg ${argName}:`,
          functionArgs[argName]
        );
      }
      functionArgs[argName] = parsedValue;
    }
  }
  console.log("[FunctionExecutor] Built function args:", functionArgs);
  return functionArgs;
}

// -----------------------------------------------------------------------------
// Execute a function in imported JS.
// Lightweight and fast. Called at runtime during request interception.
// -----------------------------------------------------------------------------
/**
 * Execute a function with the given parameters and input.
 * @param {string} domain - The domain of the function
 * @param {object} functionDetails - The details of the function to execute
 * @param {object} inputObj - The input object for the function
 * @param {Map<string, function>} funcCache - The cache of loaded functions
 * @param {boolean} fallbackDefault - The default value to return on failure
 * @returns {boolean} - The result of the function execution or the fallback default
 */
function executeFunction(
  domain,
  functionDetails,
  inputObj,
  funcCache,
  fallbackDefault = false
) {
  if (!funcCache) {
    console.error("[FunctionExecutor] Function cache is not provided");
    return fallbackDefault;
  }
  try {
    const funcPath = constructFunctionPath(domain, functionDetails.name);
    const func = funcCache.get(funcPath);
    if (!func) {
      console.error(
        `[FunctionExecutor] No function loaded for path ${funcPath}`
      );
      return fallbackDefault;
    }
    const parameterObj = functionDetails.parameters || {};
    console.log(
      `[FunctionExecutor] Executing function ${functionDetails.name} with parameters:`,
      parameterObj,
      "and input:",
      inputObj
    );

    return func(parameterObj, inputObj);
  } catch (err) {
    console.error("[FunctionExecutor] Policy execution error:", err);
    return fallbackDefault;
  }
}

// -----------------------------------------------------------------------------
// Get policy result for a given URL
// Dummy implementation for demonstration
// -----------------------------------------------------------------------------
function getPolicyResultForUrl(policy, url, method) {
  // TODO: Replace with real policy lookup logic
  if (url.includes("checkout/p/") && method === "POST") {
    return policy.rules[0];
  }
  if (url.includes("checkout/entry/cart") && method === "GET") {
    return policy.rules[1];
  }
}

// -----------------------------------------------------------------------------
// Helper: Construct function path from domain and function name
// -----------------------------------------------------------------------------
function constructFunctionPath(domain, functionName) {
  return `functions/${domain}/${functionName}.js`;
}

// -----------------------------------------------------------------------------
// Export: Preload functions and build arg spec
// -----------------------------------------------------------------------------
function setupFunctionExecution(
  policy,
  sitemap,
  domain,
  argSpecMap,
  funcCache
) {
  (async () => {
    await preloadFunctions(
      policy.rules.map((r) => constructFunctionPath(domain, r.condition.name)),
      funcCache
    );
  })();
  buildArgSpecForDomain(policy, sitemap, domain, argSpecMap);
}
