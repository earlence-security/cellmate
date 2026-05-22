# Cellmate (Firefox)

Firefox MV3 build of Cellmate. **Functionally identical to the original MV2 build** —
Mozilla's MV3 explicitly preserves blocking `webRequest`, so the entire enforcement
loop (synchronous interception, body inspection, header modification) ports over
without any compromise.

## Why Firefox

Chrome's MV3 removed `webRequestBlocking` for non-enterprise extensions, forcing a
choice between debugger-based interception (intrusive) and `declarativeNetRequest`
(can't inspect bodies). Mozilla took a different policy stance and kept the
blocking API in their MV3, so Cellmate's original code can be used as-is.

## What's different from `cellmate/` (the MV2 source)

Most files are byte-identical to the MV2 source. The manifest changes are:

| Field | MV2 | Firefox MV3 |
|---|---|---|
| `manifest_version` | 2 | 3 |
| `permissions` host pattern | `<all_urls>` | moved to `host_permissions` |
| `browser_action` | object | renamed to `action` |
| `background.persistent` | `true` | dropped (not needed; Firefox MV3 still allows persistent-style scripts) |
| `browser_specific_settings.gecko` | absent | added with extension ID |
| `browser_specific_settings.gecko.data_collection_permissions` | absent | added for Firefox add-on signing metadata |
| `web_accessible_resources` | absent | added for `blocked.html` |

`background.js` is **near-identical** to the MV2 original. The only change is in
the `extraInfoSpec` passed to `onBeforeSendHeaders.addListener` — Chrome needs
the string `"extraHeaders"` to expose the `Cookie` header; Firefox includes
`Cookie` unconditionally and rejects the unknown enum value at registration
time, which would crash the listener and break `allow_public` cookie
stripping. The Firefox build feature-detects `OnBeforeSendHeadersOptions.EXTRA_HEADERS`
and only adds the value when present, so the same source is portable across
both browsers. Everything else (popup, edit, prediction, settings, blocked,
llmClient, resources) is byte-identical to the MV2 source.

## Install (development / temporary)

1. Download Firefox **Nightly** or use a recent Firefox ≥ 142.
2. Open `about:debugging`.
3. Left sidebar → **This Firefox**.
4. Click **Load Temporary Add-on…**.
5. Navigate to `cellmate-firefox/` and select **`manifest.json`**.
6. Cellmate will appear in the list as a temporary extension.

> ⚠️ **Temporary** add-ons are unloaded when you close Firefox. For permanent install
> you need the extension signed by Mozilla (see *Signing* below).

## Install (permanent, signed)

For day-to-day use you have two options:

1. **Self-distribution signing**: zip the `cellmate-firefox/` directory and submit it
   to Mozilla's Add-ons site (AMO) as an unlisted add-on. Mozilla signs it and
   returns a `.xpi` you can install on any Firefox.
2. **Firefox Developer Edition / Nightly with `xpinstall.signatures.required = false`**:
   in `about:config`, flip this preference to `false`. Then drag a packaged `.xpi`
   into the browser. Easier but only works on Developer/Nightly builds.

For a research artifact, option 2 is usually enough.

## Quick start

Same as MV2:

1. Click the Cellmate icon in the toolbar.
2. If the current site has a bundled policy under `resources/<domain>/`, you'll see
   "Setup Policy". Click it, toggle the rules you want enabled, click Submit.
3. Background script enforces the compiled policy on all subsequent requests via
   blocking `webRequest`.

The bundled GitLab policy under `resources/gitlab.com/` can be exercised through
the same popup workflow described above. Unlike debugger-based MV3 builds, this
Firefox build has no yellow debugger banner or target-swap edge cases because it
uses Firefox's blocking `webRequest` support directly.

## What you do NOT need to do

- No `chrome://flags` toggles
- No legacy manifest version override
- No debugger permission acceptance during install
- No service-worker idle handling
- No CDP target-swap workarounds

This is the path of least resistance to a working Cellmate today. The trade-off is
that you depend on Firefox.
