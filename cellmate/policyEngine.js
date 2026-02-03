// -------------------------
// Exceptions
// -------------------------
class InvalidPolicyError extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidPolicyError";
  }
}

class PolicyDenied extends Error {
  constructor(message) {
    super(message);
    this.name = "PolicyDenied";
  }
}

// -------------------------
// Endpoint
// -------------------------
class Endpoint {
  constructor(url, method, body = null) {
    this.url = url;
    this.method = method;
    this.body = body;
  }

  static fromDict(data) {
    return new Endpoint(data.url, data.method, data.body || null);
  }
}

// -------------------------
// Action
// -------------------------
class Action {
  constructor(method, url, body = null, tags = [], semanticAction = null) {
    this.method = String(method || "").toUpperCase();
    this.url = url;
    this.body = body;

    this.tags = Array.isArray(tags) ? tags : [];

    this.semanticAction = semanticAction;

    try {
      const parsed = new URL(url);
      this.domain = parsed.hostname;
    } catch {
      this.domain = null;
    }
  }

  static fromEndpoint({ url, method, sitemap, body = null }) {
    if (!sitemap || typeof sitemap.getMatchInfo !== "function") {
      throw new Error("Action.fromEndpoint requires a Sitemap instance with getMatchInfo()");
    }
    const info = sitemap.getMatchInfo(method, url, body);
    return new Action(method, url, body, info.tags, info.semanticAction);
  }
}

// -------------------------
// Policy
// -------------------------
// Policy object format expected by this engine:
//
// {
//   // other fields can exist, but are ignored by the matcher
//   rules: [
//     { effect: "allow", action: ["read_project_deploy_token", "read_project_deploy_key"], ... },
//     { effect: "allow", action: ["update_deploy_key"], ... },
//     ...
//   ]
// }
//
// Semantics:
// - If action.semanticAction is not found in sitemap => deny.
// - If ANY rule contains action.semanticAction in its action[] => return that rule.effect.
// - Otherwise => "deny".
class Policy {
  constructor(rules = []) {
    this.rules = rules;
    this._postInit();
  }

  _postInit() {
    // Validate and normalize rules
    if (!Array.isArray(this.rules)) {
      throw new InvalidPolicyError("Policy.rules must be an array");
    }

    this.rules = this.rules.map((r, idx) => {
      if (!r || typeof r !== "object") {
        throw new InvalidPolicyError(`Policy rule at index ${idx} must be an object`);
      }
      const effect = String(r.effect || "").toLowerCase();
      if (!["allow", "deny", "allow_public"].includes(effect)) {
        throw new InvalidPolicyError(
          `Invalid rule.effect at index ${idx}: '${r.effect}'. Expected 'allow', 'deny', or 'allow_public'.`
        );
      }
      if (!("action" in r)) {
        throw new InvalidPolicyError(`Rule at index ${idx} missing required field 'action'`);
      }
      if (!Array.isArray(r.action) || r.action.some(a => typeof a !== "string")) {
        throw new InvalidPolicyError(
          `Rule.action at index ${idx} must be an array of strings (semantic_action ids)`
        );
      }

      // Normalize
      return {
        effect,
        action: r.action.slice(), // keep as-is
        description: typeof r.description === "string" ? r.description : null,
        sensitive: Boolean(r.sensitive)
      };
    });

  }

  static fromDict(data) {
    if (!data || typeof data !== "object") {
      throw new InvalidPolicyError("Policy.fromDict expects an object");
    }
    if (!Array.isArray(data.rules)) {
      throw new InvalidPolicyError("Policy object must have a 'rules' array");
    }
    return new Policy(data.rules);
  }

  evaluate(action) {
    // Require a sitemap-resolved semanticAction.
    if (!action || !action.semanticAction) return "deny";

    // Find first matching rule (policy selection/ordering is handled by caller via compiled policy)
    for (const rule of this.rules) {
      if (rule.action.includes(action.semanticAction)) {
        return rule.effect; // "allow" | "deny" | "allow_public"
      }
    }
    return "deny";
  }
}

// -------------------------
// SitemapEntry
// -------------------------
class SitemapEntry {
  constructor(method, urlTemplate, regex, semanticAction, body = null, tags = []) {
    this.method = String(method || "").toUpperCase();
    this.urlTemplate = urlTemplate;
    this.regex = regex; // RegExp
    this.semanticAction = semanticAction; // string (required)
    this.body = body || {};
    this.tags = Array.isArray(tags) ? tags : [];
  }

  match(actionMethod, actionUrl /*, actionBody */) {
    if (String(actionMethod || "").toUpperCase() !== this.method) return false;

    // Self-match for template strings (your extension uses entry.urlTemplate).
    if (actionUrl === this.urlTemplate) return true;

    // Otherwise match on compiled regex.
    return this.regex.test(actionUrl);
  }
}

// -------------------------
// Sitemap
// -------------------------
class Sitemap {
  constructor(jsonData = null) {
    this.entries = [];
    if (jsonData) {
      this.parseSitemapJson(jsonData);
    }
  }

  _compileTemplate(urlTemplate) {
    // Escape regex metacharacters other than our placeholders and '*'.
    // Approach:
    //  1) Temporarily mark placeholders and '*' then escape the rest.
    //  2) Re-introduce regex fragments.
    const PH = "__PH__";
    const STAR = "__STAR__";

    let s = String(urlTemplate);

    // Protect placeholders and '*'
    s = s.replace(/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g, `${PH}$1${PH}`);
    s = s.replace(/\*/g, STAR);

    // Escape regex metacharacters
    s = s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    // Restore wildcard: '*' => '.*'
    s = s.replaceAll(STAR, ".*");

    // Restore placeholders: {name} => (?<name>[^/]+)
    s = s.replace(new RegExp(`${PH}([a-zA-Z_][a-zA-Z0-9_]*)${PH}`, "g"), "(?<$1>[^/]+)");

    return new RegExp(`^${s}$`);
  }

  parseSitemapJson(jsonData) {
    const data = typeof jsonData === "string" ? JSON.parse(jsonData) : jsonData;
    if (!Array.isArray(data)) {
      throw new Error("Sitemap JSON must be an array of entries");
    }

    this.entries = [];

    for (const item of data) {
      const urlTemplate = item.url;
      const method = (item.method || "").toUpperCase();
      const semanticAction = item.semantic_action;

      if (!urlTemplate || !method) {
        throw new Error(`Invalid sitemap entry (missing url/method): ${JSON.stringify(item)}`);
      }
      if (!semanticAction || typeof semanticAction !== "string") {
        throw new Error(`Invalid sitemap entry (missing semantic_action): ${JSON.stringify(item)}`);
      }

      const regex = this._compileTemplate(urlTemplate);
      const body = item.body || {};
      const tags = Array.isArray(item.tags) ? item.tags : [];

      this.entries.push(new SitemapEntry(method, urlTemplate, regex, semanticAction, body, tags));
    }
  }

  // Core helper: resolve semanticAction (and tags for debug) for an action.
  getMatchInfo(actionMethod, actionUrl, actionBody = {}) {
    const method = String(actionMethod || "").toUpperCase();

    for (const entry of this.entries) {
      if (entry.match(method, actionUrl, actionBody)) {
        return { semanticAction: entry.semanticAction, tags: entry.tags || [] };
      }
    }
    return { semanticAction: null, tags: [] };
  }

  getTags(actionMethod, actionUrl, actionBody = {}) {
    return this.getMatchInfo(actionMethod, actionUrl, actionBody).tags;
  }
}

// -------------------------
// Exports
// -------------------------
export {
  Endpoint,
  Action,
  Policy,
  InvalidPolicyError,
  PolicyDenied,
  SitemapEntry,
  Sitemap
};
