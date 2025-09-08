const pingUrl = 'http://127.0.0.1:12354/ping';
const doneUrl = 'http://127.0.0.1:12354/done';

let pingRuleId = -1;

// Function to clear all existing dynamic rules
async function clearAllDynamicRules() {
    try {
        const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
        const removeRuleIds = existingRules.map(rule => rule.id);

        if (removeRuleIds.length > 0) {
            await chrome.declarativeNetRequest.updateDynamicRules({
                removeRuleIds: removeRuleIds
            });
            console.log("Successfully cleared all existing dynamic rules.");
        } else {
            console.log("No existing dynamic rules to clear.");
        }
    } catch (error) {
        console.error("Failed to clear dynamic rules:", error);
    }
}

async function setUpRules(rules) {
  let status = 'success';
  let message = '';

  // Check if the received data has the expected structure and is not corrupted
  if (rules && Array.isArray(rules) && rules.every(rule => typeof rule === 'object')) {
      console.log("Received valid rules from server:", rules);

      const allowLocalhostRule = {
          id: rules.length + 1,
          priority: 1,
          action: { type: "allow" },
          condition: {
              urlFilter: "127.0.0.1",
              resourceTypes: ["xmlhttprequest"]
          }
      };
      rules.push(allowLocalhostRule);

      pingRuleId = rules.length;

      chrome.storage.local.set({ 'dnr_rules': rules }, () => {
          if (chrome.runtime.lastError) {
              status = 'failure';
              message = 'Failed to save rules to local storage. ' + chrome.runtime.lastError.message;
              console.error(message);
          } else {
              console.log("Rules saved to local storage.");
          }
      });

  } else {
      status = 'failure';
      message = 'Received data is not a valid rules array.';
      console.error(message);
  }

  await fetch(doneUrl, {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({ status: status, message: message })
  });
  console.log("Successfully sent 'done' signal.");
}

async function startEnforcement(contentScriptPath) {
    let status = 'success';
    let message = '';

    try {
        const result = await chrome.storage.local.get('dnr_rules');
        try {
            await clearAllDynamicRules();

            await chrome.declarativeNetRequest.updateDynamicRules({
                removeRuleIds: [], 
                addRules: result.dnr_rules
            });
            console.log("Dynamic rules retrieved and applied.");
        } catch (error) {
            status = 'failure';
            message = 'Failed to apply dynamic rules. ' + error.message;
            console.error(message);
        }
    } catch (error) {
        status = 'failure';
        message = 'Failed to retrieve rules from storage. ' + error.message;
        console.error(message);
    }
    
    if (status === 'success') {
      try {
        await chrome.scripting.registerContentScripts([{
          id: 'graphql_interceptor',
          js: [contentScriptPath],
          matches: ['<all_urls>'],
          runAt: 'document_start',
          world: 'MAIN'
        }]);
        console.log("Content script registered successfully.");
      } catch (error) {
        status = 'failure';
        message = 'Failed to register content script. ' + error.message;
        console.error(message);
      }      
    }

    await fetch(doneUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status: status, message: message })
    });
    console.log("Successfully sent 'done' signal.");
}

async function endEnforcement() {
    let status = 'success';
    let message = '';

    try {
        await clearAllDynamicRules();
        console.log("All dynamic rules cleared.");

        await chrome.scripting.unregisterContentScripts({ ids: ['graphql_interceptor'] });
        console.log("Content script unregistered successfully.");
    } catch (error) {
        status = 'failure';
        message = 'Failed to end enforcement properly. ' + error.message;
        console.error(message);
    }

    await fetch(doneUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status: status, message: message })
    });
    console.log("Successfully sent 'done' signal.");
}

// This function starts the entire process
async function startProcess() {
    chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
        if (info.rule.ruleId !== pingRuleId) {
          console.log("Rule matched:", info);
        }
      });

    while (true) {
        try {
            const response = await fetch(pingUrl);
            if (response.ok) {
                const data = await response.json();

                if (data && data.operation && typeof data.operation === 'string' && data.operation !== "null") {
                    console.log("Background script received operation:", data.operation);

                    if (data.operation === "setup") {
                        const rules = data.rules;
                        await setUpRules(rules);
                    }

                    else if (data.operation === "start") {
                        const contentScriptPath = data.content_script_path;
                        await startEnforcement(contentScriptPath);
                    }

                    else if (data.operation === "finish") {
                        await endEnforcement();
                    }

                } else {
                    continue; // Skip to the next iteration if operation is null
                }
            }
        } catch (error) {
            console.error("Failed to connect to Python server. Retrying...", error);
        }
        await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds before retrying
    }
}

// Start the process when the service worker is activated
startProcess();