document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("settings-btn").addEventListener("click", () => {
    window.location.href = "settings.html";
  });
  
  document.getElementById("predict-btn").addEventListener("click", () => {
    window.location.href = "prediction.html";
  });

  const content = document.getElementById("content");
  const actionBtn = document.getElementById("action-btn");

  // Success banner logic
  const banner = document.getElementById("banner");
  const bannerText = document.getElementById("banner-text");
  const bannerClose = document.getElementById("banner-close");
  const params = new URLSearchParams(location.search);
  if (params.get("updated") === "1" && params.get("domain")) {
    bannerText.textContent = `Policy for ${params.get("domain")} successfully updated`;
    banner.style.display = "block";
  }
  bannerClose?.addEventListener("click", () => {
    banner.style.display = "none";
    // optionally clean the URL
    history.replaceState({}, "", "popup.html");
  });

  function getCurrentDomain() {
    return new Promise((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        let url = new URL(tabs[0].url);
        resolve(url.hostname);
      });
    });
  }

  const domain = await getCurrentDomain();

  // attempt to fetch and display policy for current domain
  chrome.storage.local.get(domain, (result) => {
    if (result[domain]?.policy) {
      const policy = result[domain].policy;
      const rules = policy.rules || [];
      if (rules.length > 0) {
        let html = `<p>Active rules for <b>${domain}</b>:</p><ul id="rules-list">`;
        rules.forEach((rule, i) => {
          html += `<li>${rule.description || `Rule ${i + 1}`}</li>`;
        });
        html += `</ul>`;
        content.innerHTML = html;
      } else {
        content.innerHTML = `<p>No rules found in policy for <b>${domain}</b>.</p>`;
      }
      actionBtn.textContent = "Edit Policy";
      actionBtn.hidden = false;
      actionBtn.onclick = () => (window.location.href = "edit.html");
    } else {
      content.innerHTML = `<p>No policy found for domain <b>${domain}</b>.</p>`;
      actionBtn.textContent = "Setup Policy";
      actionBtn.hidden = false;
      actionBtn.onclick = () => (window.location.href = "edit.html");
    }
  });
});
