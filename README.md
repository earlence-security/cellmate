# Cellmate

Automating browser tasks with agents can be risky. Secure your browser session with Cellmate, a lightweight sandboxing framework for browser use agents.

## Features

- Lightweight sandboxing
- Configurable security policies
- Easy to use

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/earlence-security/cellmate.git
   ```
3. In your Chromium installation*, navigate to ```chrome://extensions/```.
4. Enable **Developer mode** in the top-right corner.
5. Click **Load unpacked** and select the cellmate directory located at the root of the cloned project.
6. Verify that the **Cellmate** extension appears in the list and is toggled on.
   
#### *Note
Cellmate currently relies on the ```webRequestBlocking``` permission from Manifest V2. Because MV2 support has been removed from recent Chromium releases, you may need an older version of Chromium to run Cellmate. We have confirmed that Cellmate works correctly on Chromium versions up to **138**, after enabling the **"Allow legacy extension manifest versions"** flag in ```chrome://flags/```.

## Quick start
1. Click the Cellmate icon to open the popup window.
2. If the current site already has a policy*, you’ll see its **Active rules**.  
   - Click **Edit Policy** to change it.  
   - If there’s no policy yet, click **Setup Policy**.
3. (Optional) Open **Settings** to or add your API key, then open **Policy Prediction** to get LLM‑based suggestions.

#### *Note
Currently we have only implemented a partial set of policy for GitLab for demoing purpose. You can find how we are instantiate policies and agent sitemap for GitLab by navigating to ```cellmate/resources/gitlab.com``` from the root of our project.
**
