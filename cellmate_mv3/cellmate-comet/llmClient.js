/**
 * Low-level fetch wrapper for Anthropic Messages API.
 * Throws with a readable error if HTTP is not ok.
 */
async function anthropicFetch({ apiKey, payload }) {
  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
      "anthropic-dangerous-direct-browser-access": "true"
    },
    body: JSON.stringify(payload)
  });

  const text = await resp.text().catch(() => "");
  if (!resp.ok) {
    throw new Error(`LLM HTTP ${resp.status}: ${text || resp.statusText}`);
  }
  return text ? JSON.parse(text) : {};
}

/**
 * Ask Anthropic for rule suggestions for a given domain + task.
 * - Builds the tool schema internally from `rulesMap`.
 * - Returns { suggestedRules: {slug:boolean}, description: string, raw }.
 */
export async function requestPolicySuggestions({
  apiKey,
  userTask,
  rulesMap,   // { slug: { description: string, ...ruleObject } }
  domain,
  model = "claude-sonnet-4-5",
  maxTokens = 1024
}) {
  // Build tool schema inline (merged builder)
  const ruleProps = {};
  const ruleReq = [];
  for (const [slug, ruleObj] of Object.entries(rulesMap)) {
    ruleProps[slug] = {
      type: "boolean",
      description: ruleObj?.description || ""
    };
    ruleReq.push(slug);
  }

  const tool = {
    name: "policy_suggestion",
    description:
      `Given the provided user task on the domain ${domain}, suggest a set of least privileges needed to complete that task. ` +
      `Privileges are expressed with rules, with each rule representing some set of privilege on the given domain. ` +
      `Suggest using a well-structured JSON object, in which, in their provided order, rules are assigned either True or False ` +
      `depending on whether privileges granted by a given rule is required to enable the user task.`,
    input_schema: {
      type: "object",
      properties: {
        suggested_rules: {
          type: "object",
          description:
            "The set of suggested rules based on provided user task. Input object should include all provided rules as keys with boolean values that indicate whether each rule is required.",
          properties: ruleProps,
          required: ruleReq,
          additionalProperties: false   // boolean, not string
        },
        description: {
          type: "string",
          description: "Provide some reasoning for the suggested rules."
        }
      },
      required: ["suggested_rules", "description"]
    }
  };

  const payload = {
    model,
    max_tokens: maxTokens,
    tools: [tool],
    tool_choice: { type: "tool", name: "policy_suggestion" },
    system: "You suggest least-privilege policies. If the user's task is unrelated to the domain's functionality, " +
            "it is correct to suggest no rules (i.e., mark every rule as false). Avoid over-granting."
, 
    messages: [
      {
        role: "user",
        content:
          `Suggest a set of rules of the user task: ${userTask}.\n\n` +
          `Domain: ${domain}\n` +
          `Instructions:\n` +
          `- Only mark a rule true if it is necessary for the task on this domain.\n` +
          `- If the task is unrelated to what this domain/app does, set ALL rules to false and explain why in the description.\n` +
          `- Prefer the smallest set of rules needed to complete the task.\n`
      }
    ]
  };

  const data = await anthropicFetch({ apiKey, payload });

  // Expect a tool_use block named policy_suggestion
  const tu = (data.content || []).find(
    c => c?.type === "tool_use" && c.name === "policy_suggestion"
  );

  const input = tu?.input || {};
  const suggestedRules = input.suggested_rules || {};
  const description = input.description || "";

  // Logging for debugging
  console.log("[LLM] suggested_rules:", suggestedRules);
  console.log("[LLM] description:", description);

  return { suggestedRules, description, raw: data };
}

/**
 * Suggest relevant domains for a free-text user task.
 * Implemented "based on" the same plumbing as requestPolicySuggestions:
 * uses the same anthropicFetch wrapper & message style (no tool schema needed here).
 *
 * Returns: string[] of hostnames (normalized lowercase, no scheme).
 */
export async function requestDomainSuggestions({ apiKey, userTask, maxDomains = 8 }) {
  const systemHint =
    "You are a browser policy assistant. Output ONLY a JSON array of hostnames (strings). " +
    "No prose, no code blocks, no explanations. Return the most specific hostnames possible " +
    "(prefer subdomains when relevant). Do not include protocols, ports, paths, or wildcards.";

  const payload = {
    model: "claude-sonnet-4-5",
    max_tokens: 512,
    system: systemHint,
    messages: [
      {
        role: "user",
        content:`
Given the user's task: ${userTask}\n
List up relevant domain that the task indicates explicitly that the browser would to visit to perform the task.\n\n
Return a strict JSON array of domain names only.\n\n
Guidelines:\n
- **Only** select domains **explicitly** mentioned in the provided task where the task needed to be performed on and **DO NOT** make inference beyond that.\n
- If No domains are **explicitly** mentioned, return an empty array, i.e. []\n
- DO NOT include domain names if it only appears as a descriptor of a subject (i.e. Dell laptop)
- Only include hostname found in the list in your output JSON array.\n
- Prefer subdomains when the product/service is tied to one (e.g., "mail.google.com" for Gmail, not "google.com").\n
- If an app uses multiple specific subdomains, list them separately.\n
- Do not include unrelated sibling subdomains (e.g., exclude "calendar.google.com" for a Gmail-only task).\n
- Do not include schemes, ports, paths, or wildcards.\n\n
- Return **strictly** the required JSON array, and nothing else (including trailing spaces, symbols, keywords)\n\n
Examples of correct outputs:\n
["mail.google.com", "apis.google.com"]\n
["amazon.com"]\n\n
Example of correct prediction:\n
task: "Search for 'birthday candles' on amazon and add the cheapest option to my shopping cart."
prediction: ["amazon.com"]\n
Reason: The task dictates to go to amazon to make the purchase, which the prediction is correct.
Example of incorrect prediction:\n\n
task: "Go to linkedin.com and send a connect request to Steve from Microsoft."
prediction: ["linkedin.com", "microsoft.com"]\n
Reason: The task requires to navigate to linkedin, which the prediction successfully includes, however, the term "Microsoft" mentioned in the task is strictly for filtering out a candidate Steve from linkedin and in nowhere in the task require the navigation to "microsoft.com", so predicting "microsoft.com" is incorrect.
`
      }
    ]
  };

  const data = await anthropicFetch({ apiKey, payload });

  const first = (data.content || [])[0];
  let raw = "";
  if (first?.type === "text" && typeof first.text === "string") {
    raw = first.text.trim();
  } else {
    raw = JSON.stringify(data.content || []);
  }

  let arr = [];
  try {
    arr = JSON.parse(raw);
  } catch {
    const m = raw.match(/\[[\s\S]*\]/);
    if (m) {
      try { arr = JSON.parse(m[0]); } catch {}
    }
  }

  // IMPORTANT: keep subdomains EXACT; do not strip "www."
  const norm = (s) => {
    try {
      if (/^https?:\/\//i.test(s)) return new URL(s).hostname.toLowerCase();
      return String(s || "").trim().toLowerCase(); // keep 'www.' if provided
    } catch {
      return String(s || "").trim().toLowerCase();
    }
  };

  // Dedupe while preserving order
  const seen = new Set();
  const domains = [];
  if (Array.isArray(arr)) {
    for (const item of arr.map(norm).filter(Boolean)) {
      if (!seen.has(item)) { seen.add(item); domains.push(item); }
    }
  }

  console.log("[LLM] domain suggestions:", domains);
  return domains;
}
