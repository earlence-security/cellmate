// MV3 service worker.
//
// Blocking is implemented with declarativeNetRequest dynamic rules, rebuilt
// whenever chrome.storage.local changes. Conceptual model preserved from the
// MV2 version:
//
//   [1] Predicted-allowlist gate (strict exact hostname; redirects main_frame
//       to blocked.html, cancels subresources)
//   [2] Untrusted-domain gate (blocks requests whose dest has no policy AND
//       isn't whitelisted by the current page's policy)
//   [3] Target rules: "deny" blocks, "allow_public" allows + strips Cookie
//
// Caveat: body-pattern target rules (entry.body) cannot be expressed in DNR
// (DNR cannot inspect request bodies). Those entries are skipped with a
// warning. If body-aware enforcement is needed, it has to move into a
// content-script fetch/XHR interceptor on the page.

const EXT_ID = chrome.runtime.id;
const BLOCKED_REDIRECT_PATH =
  "/blocked.html?reason=predicted_allowlist&active=true";

const RESOURCE_ALL = [
  "main_frame", "sub_frame", "stylesheet", "script", "image", "font",
  "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket",
  "webtransport", "webbundle", "other"
];
const RESOURCE_NON_MAIN = RESOURCE_ALL.filter(r => r !== "main_frame");

// Templates: {param} -> ([^/]+) and * -> .*  (same grammar as the MV2 version)
function compileTemplateToRegexString(template) {
  let pattern = template.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  pattern = pattern
    .replace(/\\\{[a-zA-Z_][a-zA-Z0-9_]*\\\}/g, "([^/]+)")
    .replace(/\\\*/g, ".*");
  return `^${pattern}$`;
}

function reEscape(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

// Match only the exact hostname (any scheme/port/path). DNR's requestDomains
// is subdomain-inclusive, so we need regex for the strict-exact behavior the
// predicted allowlist depends on.
function strictHostRegex(host) {
  return `^https?://${reEscape(host)}(:\\d+)?(/.*)?$`;
}

async function readState() {
  const all = await chrome.storage.local.get(null);

  const disallowUntrusted =
    typeof all.disallow_untrusted_domains === "boolean"
      ? all.disallow_untrusted_domains
      : true;
  const predictedAllowlistActive = !!all.predicted_domain_allowlist_active;
  const predictedAllowlist = Array.isArray(all.predicted_domain_allowlist)
    ? all.predicted_domain_allowlist.map(String).filter(Boolean)
    : [];

  const policies = [];
  const targets = [];
  let skippedBody = 0;

  for (const [key, value] of Object.entries(all)) {
    if (!value || typeof value !== "object") continue;
    if (value.policy) {
      const allowedDomains = Array.isArray(value.policy.allowed_domains)
        ? value.policy.allowed_domains.map(String).filter(Boolean)
        : [];
      policies.push({ domain: key, allowedDomains });
    }
    if (Array.isArray(value.target_requests)) {
      for (const t of value.target_requests) {
        if (t.body && typeof t.body === "object" && Object.keys(t.body).length > 0) {
          console.warn(
            "[bg] Skipping body-pattern target rule (not enforceable under MV3 DNR):",
            key, t.method, t.url
          );
          skippedBody++;
          continue;
        }
        targets.push({
          domain: key,
          method: (t.method || "").toUpperCase(),
          urlTemplate: t.url,
          decision: t.decision
        });
      }
    }
  }

  return {
    disallowUntrusted,
    predictedAllowlistActive,
    predictedAllowlist,
    policies,
    targets,
    skippedBody
  };
}

function buildRules(state) {
  const {
    disallowUntrusted,
    predictedAllowlistActive,
    predictedAllowlist,
    policies,
    targets
  } = state;

  const rules = [];
  let nextId = 1;
  const id = () => nextId++;

  // -------- Default-deny tier (priority 10) --------
  if (predictedAllowlistActive) {
    rules.push({
      id: id(),
      priority: 10,
      action: {
        type: "redirect",
        redirect: { extensionPath: BLOCKED_REDIRECT_PATH }
      },
      condition: {
        urlFilter: "|http",
        resourceTypes: ["main_frame"],
        excludedInitiatorDomains: [EXT_ID]
      }
    });
    rules.push({
      id: id(),
      priority: 10,
      action: { type: "block" },
      condition: {
        urlFilter: "|http",
        resourceTypes: RESOURCE_NON_MAIN,
        excludedInitiatorDomains: [EXT_ID]
      }
    });
  } else if (disallowUntrusted) {
    rules.push({
      id: id(),
      priority: 10,
      action: { type: "block" },
      condition: {
        urlFilter: "|http",
        resourceTypes: RESOURCE_ALL,
        excludedInitiatorDomains: [EXT_ID]
      }
    });
  }

  // -------- Allow tier (priority 100) --------

  if (predictedAllowlistActive) {
    for (const host of predictedAllowlist) {
      rules.push({
        id: id(),
        priority: 100,
        action: { type: "allow" },
        condition: {
          regexFilter: strictHostRegex(host),
          resourceTypes: RESOURCE_ALL
        }
      });
    }
  } else if (disallowUntrusted) {
    // Untrusted gate only: any destination that has its own policy is allowed.
    // (When the predicted-allowlist gate is on, only the strict allowlist counts.)
    const policyDomains = policies.map(p => p.domain).filter(Boolean);
    if (policyDomains.length > 0) {
      rules.push({
        id: id(),
        priority: 100,
        action: { type: "allow" },
        condition: {
          requestDomains: policyDomains,
          resourceTypes: RESOURCE_ALL
        }
      });
    }
  }

  // Cross-domain: if the initiating page's policy whitelists the destination,
  // allow it. Applies to both gates.
  if (predictedAllowlistActive || disallowUntrusted) {
    for (const { domain, allowedDomains } of policies) {
      if (!allowedDomains.length) continue;
      rules.push({
        id: id(),
        priority: 100,
        action: { type: "allow" },
        condition: {
          initiatorDomains: [domain],
          requestDomains: allowedDomains,
          resourceTypes: RESOURCE_ALL
        }
      });
    }
  }

  // -------- Target rules (priority 110/120) --------
  for (const t of targets) {
    const cond = {
      regexFilter: compileTemplateToRegexString(t.urlTemplate),
      requestDomains: [t.domain],
      resourceTypes: RESOURCE_ALL
    };
    if (t.method) cond.requestMethods = [t.method.toLowerCase()];

    if (t.decision === "deny") {
      rules.push({
        id: id(),
        priority: 120,
        action: { type: "block" },
        condition: cond
      });
    } else if (t.decision === "allow_public") {
      rules.push({
        id: id(),
        priority: 110,
        action: { type: "allow" },
        condition: cond
      });
      rules.push({
        id: id(),
        priority: 110,
        action: {
          type: "modifyHeaders",
          requestHeaders: [{ header: "cookie", operation: "remove" }]
        },
        condition: cond
      });
    }
  }

  return rules;
}

let rebuildPending = false;
async function rebuildRules() {
  if (rebuildPending) return;
  rebuildPending = true;
  try {
    const state = await readState();
    const rules = buildRules(state);

    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map(r => r.id),
      addRules: rules
    });

    console.log("[bg] DNR rules installed:", rules.length,
      "| disallowUntrusted=", state.disallowUntrusted,
      "| predictedAllowlistActive=", state.predictedAllowlistActive,
      "| predictedAllowlist=", state.predictedAllowlist.length,
      "| policies=", state.policies.length,
      "| targets=", state.targets.length,
      "| skippedBody=", state.skippedBody
    );
  } catch (e) {
    console.error("[bg] rebuildRules failed:", e);
  } finally {
    rebuildPending = false;
  }
}

// Debounce burst updates from storage.set() during multi-write flows.
let debounceTimer = null;
function scheduleRebuild() {
  if (debounceTimer) return;
  debounceTimer = setTimeout(() => {
    debounceTimer = null;
    rebuildRules();
  }, 50);
}

// Factory default for the untrusted-domain toggle.
chrome.storage.local.get("disallow_untrusted_domains", res => {
  if (typeof res.disallow_untrusted_domains !== "boolean") {
    chrome.storage.local.set({ disallow_untrusted_domains: true });
  }
});

chrome.runtime.onInstalled.addListener(() => rebuildRules());
chrome.runtime.onStartup.addListener(() => rebuildRules());
chrome.storage.onChanged.addListener((_changes, area) => {
  if (area === "local") scheduleRebuild();
});

// Cover the case where the service worker boots from an event other than
// onInstalled/onStartup (e.g. a fresh message) and we haven't rebuilt yet.
rebuildRules();
