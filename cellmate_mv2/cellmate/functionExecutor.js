// -----------------------------------------------------------------------------
// Helper Functions for Function Execution and Argument Building
// -----------------------------------------------------------------------------

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
// Helper: Construct function path from domain and function name
// -----------------------------------------------------------------------------
function constructFunctionPath(domain, functionName) {
  return `resources/${domain}/functions/${functionName}.js`;
}

