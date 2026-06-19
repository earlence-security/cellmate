const PORT_DISPLAY_MAP = { "8023": "gitlab.com", "9999": "reddit.com" };

function getDisplayDomain(origin) {
  try {
    const port = new URL(origin).port;
    return PORT_DISPLAY_MAP[port] || origin;
  } catch {
    return origin;
  }
}

document.getElementById("back-btn").addEventListener("click", () => window.close());

document.getElementById("stop-btn").addEventListener("click", () => {
  // Placeholder — stop agent functionality not yet implemented
});

const params = new URLSearchParams(location.search);
if (params.get("updated") === "1" && params.get("domain")) {
  const banner = document.getElementById("banner");
  document.getElementById("banner-text").textContent =
    `Policy for ${params.get("domain")} successfully updated`;
  banner.style.display = "block";
  document.getElementById("banner-close").addEventListener("click", () => {
    banner.style.display = "none";
    history.replaceState({}, "", "agent.html");
  });
}

(async function loadPolicies() {
  const container = document.getElementById("policies");

  const all = await new Promise((res, rej) =>
    chrome.storage.local.get(null, r =>
      chrome.runtime.lastError ? rej(chrome.runtime.lastError) : res(r)
    )
  );

  const domains = Object.entries(all).filter(([, val]) => val?.policy?.rules);

  if (domains.length === 0) {
    container.innerHTML = `<div class="no-policies">No active policies found.</div>`;
    return;
  }

  for (const [domain, entry] of domains) {
    const slugs = entry.selected_rule_slugs || [];
    const rules = entry.policy.rules || [];

    let preview;
    if (slugs.length > 0) {
      const rest = slugs.length > 1 ? `, +${slugs.length - 1} more` : "";
      preview = `{"${slugs[0]}": ...${rest}}`;
    } else if (rules.length > 0) {
      preview = `${rules.length} rule${rules.length !== 1 ? "s" : ""} enabled`;
    } else {
      preview = "No rules enabled";
    }

    const card = document.createElement("div");
    card.className = "policy-card";
    card.innerHTML = `
      <a class="policy-domain" href="${domain}" target="_blank">${getDisplayDomain(domain)}</a>
      <div class="policy-preview">${preview}</div>
    `;
    container.appendChild(card);
  }
})();
