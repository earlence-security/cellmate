// background.js (module)
let wasmExports = null;
let wasmMemory = null;
const enc = new TextEncoder();
const dec = new TextDecoder();

// --- loadWasm must be called at startup and set wasmExports & wasmMemory ---
async function loadWasm(url) {
  const resp = await fetch(url);
  const bytes = await resp.arrayBuffer();
  const module = await WebAssembly.compile(bytes); // compile explicitly
  const instance = await WebAssembly.instantiate(module); // instantiate safely
  wasmExports = instance.exports;
  wasmMemory = wasmExports.memory;
  if (!wasmExports.alloc || !wasmExports.dealloc || !wasmExports.eval_policy) {
    throw new Error("WASM missing required exports");
  }
  console.log("WASM loaded and ready");
}

// Safe helper to get fresh memory view (memory.buffer can grow)
function getMemoryView() {
  return new Uint8Array(wasmMemory.buffer);
}

// Marshal JS object to WASM memory, return {ptr,len}
function passObject(obj) {
  const s = JSON.stringify(obj);
  const bytes = enc.encode(s);
  const ptr = wasmExports.alloc(bytes.length);
  getMemoryView().set(bytes, ptr);
  return { ptr, len: bytes.length };
}

// free memory
function free(ptr, len) {
  wasmExports.dealloc(ptr, len);
}

// run policy synchronously, returns boolean; fallbackDefault is bool when wasm not ready or error
function runPolicySync(inputObj, fallbackDefault = false) {
  if (!wasmExports) {
    // wasm not ready — choose default (deny/allow)
    return fallbackDefault;
  }
  try {
    const { ptr, len } = passObject(inputObj);
    const res = wasmExports.eval_policy(ptr, len); // synchronous i32
    free(ptr, len);
    return !!res;
  } catch (e) {
    console.error("Policy call failed:", e);
    return fallbackDefault;
  }
}

// Fetch the DOM element value from a tab
async function fetchDomValueFromTab(tabId, selector, timeout = 10000) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: (sel, timeo) => {
        return new Promise((resolve) => {
          const waitForElement = (selector, timeoutMs) => {
            const start = Date.now();
            const check = () => {
              const el = document.querySelector(selector);
              if (el) return resolve(el.innerText);
              if (Date.now() - start >= timeoutMs) return resolve(null);
              setTimeout(check, 200);
            };
            check();
          };
          if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", () =>
              waitForElement(sel, timeo)
            );
          } else {
            waitForElement(sel, timeo);
          }
        });
      },
      args: [selector, timeout]
    });
    return results?.[0]?.result || null;
  } catch (e) {
    console.error("DOM fetch failed:", e);
    return null;
  }
}

/* Build a simple input JSON describing the request.
   request is the listener's details object.
*/
function buildInputFromRequestDetails(details) {
  const input = {
    method: details.method,
    url: details.url,
    // headers not present in onBeforeRequest for many browsers; you can use onBeforeSendHeaders to capture them.
    headers: {}, 
    timeStamp: details.timeStamp,
    tabId: details.tabId
  };

  // requestBody: available if you registered for "requestBody"
  if (details.requestBody) {
    if (details.requestBody.raw && details.requestBody.raw.length > 0) {
      // raw[0].bytes is an ArrayBuffer (in Chrome)
      try {
        const raw = details.requestBody.raw[0];
        // In Chrome, raw.bytes is a Uint8Array-like in the details object.
        const arr = raw.bytes || raw; // defensive
        const bodyText = dec.decode(arr);
        input.body = bodyText;
      } catch (err) {
        // fallback: try formData if present
        if (details.requestBody.formData) {
          input.formData = details.requestBody.formData;
        }
      }
    } else if (details.requestBody.formData) {
      input.formData = details.requestBody.formData;
    }
  }

  return input;
}

// --- Register webRequest listener ---
// Limit to URLs you care about for perf. Example below intercepts POSTs to /api/*
const filter = {
  urls: ["https://www.amazon.com/checkout/entry/cart*"], // change to the APIs you care about
  types: ["main_frame"]    // only network types you care about
};

// extraInfoSpec must include "blocking" and "requestBody" to get bodies (for POST).
chrome.webRequest.onBeforeRequest.addListener(
  async function(details) {
    // Build input object
    // const input = buildInputFromRequestDetails(details);
    const input = null;

    // Fetch DOM value (e.g., total amount) from the tab
    if (typeof details.tabId === "number" && details.tabId >= 0) {
      const domValue = await fetchDomValueFromTab(details.tabId, "#sc-subtotal-amount-buybox > span");
      if (domValue) {
        input = {"total_amount": domValue};
      }
    }

    console.log("Policy input:", input);

    // Decide default behavior if wasm isn't ready; choose false (deny) for safety or true to prefer allow
    const defaultAllow = false;

    // Call policy synchronously
    const allowed = runPolicySync(input, defaultAllow);

    if (!allowed) {
      // Cancel the request
      return { cancel: true };
    }
    // else allow by returning nothing / empty object
    return {};
  },
  filter,
  ["blocking", "requestBody"]
);

// --- Initialize WASM at startup ---
self.addEventListener('activate', () => {
  // no-op; just to keep worker alive for example
});
(async () => {
  // load wasm early; replace with your hosted URL
  try {
    await loadWasm("http://localhost:8080/policy_wasm.wasm");
  } catch (e) {
    console.error("Failed to load policy wasm:", e);
  }
})();

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "ping") console.log("Service worker awake!");
});
