// blocked.js
(function () {
  const params = new URLSearchParams(location.search);
  const reason  = params.get("reason") || "";     // e.g. "predicted_allowlist"
  const dest    = params.get("dest")   || "";     // destination hostname
  const current = params.get("current")|| "";     // current page hostname
  const active  = params.get("active") === "true";

  const $ = (id) => document.getElementById(id);
  const whyEl      = $("why");
  const domainsDiv = $("domainsBlock");
  const listEl     = $("allowedList");
  const promptEl   = $("prompt");

  // Message explaining the block
  const baseMsg =
    "This navigation has been blocked by Cellmate, a sandboxing extension for browser use agents, " +
    "as it has violated the current navigation policy, likely because this action is in violation of the agent’s original task.";

  // Tailor slightly if we know it’s the predicted-allowlist gate
//   if (reason === "predicted_allowlist") {
//     whyEl.textContent = baseMsg + (active ? " (Domain restriction is active.)" : "");
//   } else {
//     whyEl.textContent = baseMsg;
//   }
  whyEl.textContent = baseMsg;

  // Load the currently active allowlist and the current page’s allowed_domains, then show union
  chrome.storage.local.get(
    ["predicted_domain_allowlist_active", "predicted_domain_allowlist", current],
    (res) => {
      const gateActive = !!res.predicted_domain_allowlist_active;
      const allowlist  = Array.isArray(res.predicted_domain_allowlist) ? res.predicted_domain_allowlist : [];

      const policyAllowed = (res[current]?.policy?.allowed_domains) || [];
      const merged = Array.from(new Set([...(gateActive ? allowlist : []), ...policyAllowed]))
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b));

      if (merged.length > 0) {
        domainsDiv.style.display = "block";
        for (const d of merged) {
          const li = document.createElement("li");
          li.textContent = d;
          listEl.appendChild(li);
        }
      }

      // Final instruction for the agent
      promptEl.textContent =
        "If you believe this navigation is necessary to accomplish the original task, ask the user to update the policy accordingly.";
    }
  );
})();
