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
 * Ask Claude to suggest which rules to enable for a given domain + task.
 * Returns { suggestedRules: {slug: boolean}, description: string, raw }.
 */
export async function requestPolicySuggestions({
  apiKey,
  userTask,
  rulesMap,
  domain,
  model = "claude-haiku-4-5-20251001",
  maxTokens = 1024
}) {
  const ruleProps = {};
  const ruleReq = [];
  for (const [slug, ruleObj] of Object.entries(rulesMap)) {
    ruleProps[slug] = { type: "boolean", description: ruleObj?.description || "" };
    ruleReq.push(slug);
  }

  const tool = {
    name: "policy_suggestion",
    description:
      `Given the provided user task on the domain ${domain}, suggest a set of least privileges needed to complete that task. ` +
      `Privileges are expressed with rules, with each rule representing some set of privilege on the given domain. ` +
      `Suggest using a well-structured JSON object, in which rules are assigned either True or False ` +
      `depending on whether privileges granted by a given rule are required to enable the user task.`,
    input_schema: {
      type: "object",
      properties: {
        suggested_rules: {
          type: "object",
          description:
            "The set of suggested rules based on provided user task. Include all provided rules as keys with boolean values.",
          properties: ruleProps,
          required: ruleReq,
          additionalProperties: false
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
    system:
      "You suggest least-privilege policies. If the user's task is unrelated to the domain's functionality, " +
      "it is correct to suggest no rules (i.e., mark every rule as false). Avoid over-granting.",
    messages: [
      {
        role: "user",
        content:
          `Suggest a set of rules for the user task: ${userTask}.\n\n` +
          `Domain: ${domain}\n` +
          `Instructions:\n` +
          `- Only mark a rule true if it is necessary for the task on this domain.\n` +
          `- If the task is unrelated to what this domain/app does, set ALL rules to false.\n` +
          `- Prefer the smallest set of rules needed to complete the task.\n`
      }
    ]
  };

  const data = await anthropicFetch({ apiKey, payload });

  const tu = (data.content || []).find(
    c => c?.type === "tool_use" && c.name === "policy_suggestion"
  );
  const input = tu?.input || {};
  const suggestedRules = input.suggested_rules || {};
  const description = input.description || "";

  console.log("[LLM] suggested_rules:", suggestedRules);
  console.log("[LLM] description:", description);

  return { suggestedRules, description, raw: data };
}

/**
 * Ask Claude to suggest relevant domains for a free-text user task.
 * Returns string[] of hostnames.
 */
export async function requestDomainSuggestions({ apiKey, userTask, maxDomains = 8 }) {
  const systemHint =
    "You are a browser policy assistant. Output ONLY a JSON array of hostnames (strings). " +
    "No prose, no code blocks, no explanations. Return the most specific hostnames possible " +
    "(prefer subdomains when relevant). Do not include protocols, ports, paths, or wildcards.";

  const payload = {
    model: "claude-haiku-4-5-20251001",
    max_tokens: 512,
    system: systemHint,
    messages: [
      {
        role: "user",
        content:
          `Given the user's task: ${userTask}\n\n` +
          `List relevant domains that the task explicitly requires the browser to visit.\n\n` +
          `Return a strict JSON array of domain names only.\n\n` +
          `Guidelines:\n` +
          `- Only select domains **explicitly** mentioned in the task — do not infer beyond that.\n` +
          `- If no domains are explicitly mentioned, return [].\n` +
          `- Do not include domains that appear only as descriptors (e.g., "Dell laptop" does not imply dell.com).\n` +
          `- Prefer subdomains when the service is tied to one (e.g., "mail.google.com" for Gmail).\n` +
          `- Do not include schemes, ports, paths, or wildcards.\n` +
          `- Return strictly the JSON array, nothing else.\n\n` +
          `Examples:\n` +
          `task: "Search for birthday candles on amazon and add the cheapest to cart."\n` +
          `output: ["amazon.com"]\n\n` +
          `task: "Go to linkedin.com and send a connect request to Steve from Microsoft."\n` +
          `output: ["linkedin.com"]  (microsoft.com is only a descriptor, not a navigation target)`
      }
    ]
  };

  const data = await anthropicFetch({ apiKey, payload });

  const first = (data.content || [])[0];
  let raw = first?.type === "text" ? first.text.trim() : JSON.stringify(data.content || []);

  let arr = [];
  try {
    arr = JSON.parse(raw);
  } catch {
    const m = raw.match(/\[[\s\S]*\]/);
    if (m) { try { arr = JSON.parse(m[0]); } catch {} }
  }

  const norm = (s) => {
    try {
      if (/^https?:\/\//i.test(s)) return new URL(s).hostname.toLowerCase();
      return String(s || "").trim().toLowerCase();
    } catch {
      return String(s || "").trim().toLowerCase();
    }
  };

  const seen = new Set();
  const domains = [];
  if (Array.isArray(arr)) {
    for (const item of arr.map(norm).filter(Boolean)) {
      if (!seen.has(item)) { seen.add(item); domains.push(item); }
    }
  }

  console.log("[LLM] domain suggestions:", domains);
  return domains.slice(0, maxDomains);
}
