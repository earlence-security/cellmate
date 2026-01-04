// -----------------------------------------------------------------------------
// Data structure: argument specifications
// -----------------------------------------------------------------------------

// argSpec: Map storing argument source/type specifications
// domain -> semantic_action -> arg_name -> { source, type }
// Example: argSpec.get("amazon.com").get("place_order").get("total_amount") = { source: {...}, type: "number" }

// Getter: Lookup argument specification for a specific argument
function lookupArgSpec(domain, action, argName, argSpecMap) {
  return argSpecMap.get(domain)?.get(action)?.get(argName) ?? null;
}

// Getter: Get all argument specifications for a specific domain
function getArgSpecForDomain(domain, argSpecMap) {
  return argSpecMap.get(domain) || null;
}

// Setter: Build argument specification map for a domain
function buildArgSpecForDomain(policy, sitemap, domain, argSpecMap) {
  if (!argSpecMap) {
    console.error("[PolicyRunner] Arg config map is not provided");
    return;
  }
  let domainArgSpec = argSpecMap.get(domain);
  if (!domainArgSpec) {
    domainArgSpec = new Map();
    argSpecMap.set(domain, domainArgSpec);
  }
  for (const rule of policy.rules) {
    // Find arg specifications for this action from sitemap.
    // Note that not all args specified in the sitemap are needed by the rule.
    if (domainArgSpec.has(rule.action)) {
      console.debug(
        `[PolicyRunner] Arg spec for action ${rule.action} already exists, skip retrieval`
      );
      continue;
    }
    const ruleArgSpec = new Map();
    domainArgSpec.set(rule.action, ruleArgSpec);
    const actionArgSpecInfo = sitemap.find(
      (item) => item.semantic_action === rule.action
    )?.args;
    if (!actionArgSpecInfo) {
      console.error(
        `[PolicyRunner] No arg spec found in sitemap for action ${rule.action}`
      );
      continue;
    }
    for (const argName of rule.condition.args || []) {
      const argSpec = actionArgSpecInfo?.[argName];
      if (argSpec) {
        // domain -> semantic_action -> arg_name -> { source, type }
        ruleArgSpec.set(argName, {
          source: argSpec.source,
          type: argSpec.type,
        });
      }
    }
  }
  console.log(
    `[PolicyRunner] Built arg spec for domain ${domain}:`,
    domainArgSpec
  );
}
