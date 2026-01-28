console.log("Content script loaded.");

// ---- READY + initial page update ----
chrome.runtime.sendMessage({ type: "CS_READY" });
// chrome.runtime.sendMessage({ type: "PAGE_UPDATED" });

// ---- Listen for block events ----
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type !== "BLOCK_EVENT") return;

  console.log("Received BLOCK_EVENT:", msg);

  showOrUpdateBlockBanner(msg);
});

// ---- Helpers ----
function getTopFixedOffset() {
  const el = document.elementFromPoint(0, 0);
  if (!el) return 0;

  const rect = el.getBoundingClientRect();
  const style = getComputedStyle(el);

  // If the element at top is fixed, use its height
  if (style.position === "fixed") {
    return rect.height || 0;
  }
  return 0;
}

// ---- Banner (update-safe) ----
function showOrUpdateBlockBanner({ reason, url, method }) {
  const BANNER_HEIGHT = 48;
  let banner = document.getElementById("__EXT_BLOCK_BANNER__");

  const topOffset = getTopFixedOffset();

  if (!banner) {
    banner = document.createElement("div");
    banner.id = "__EXT_BLOCK_BANNER__";

    Object.assign(banner.style, {
      position: "fixed",
      top: `${topOffset}px`,     // 👈 place below navbar
      left: "0",
      right: "0",
      height: `${BANNER_HEIGHT}px`,
      zIndex: "2147483647",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: "0 14px",
      background: "#b00020",
      color: "white",
      fontSize: "14px",
      fontFamily: "sans-serif",
      boxSizing: "border-box",
      boxShadow: "0 2px 6px rgba(0,0,0,0.3)"
    });

    // Push page down by banner height (so it doesn't overlap content)
    const html = document.documentElement;
    html.style.marginTop = `calc(${html.style.marginTop || "0px"} + ${BANNER_HEIGHT}px)`;

    html.appendChild(banner);
  }

  banner.textContent =
    `⛔ You have performed an action unrelated to your original task. Please focus on your original task from user.
    Detail: request ${method} ${url} blocked by ceLLMate policy.`;
}

// ---- Detect page updates (SPA-safe) ----
let mutationTimer = null;

const observer = new MutationObserver(() => {
  if (mutationTimer) return;

  mutationTimer = setTimeout(() => {
    mutationTimer = null;
    chrome.runtime.sendMessage({ type: "PAGE_UPDATED" });
  }, 200);
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true
});
