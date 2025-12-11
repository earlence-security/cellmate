
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
    this.method = method.toUpperCase();
    this.url = url;
    this.body = body;
    this.tags = tags;
    this.semanticAction = semanticAction;

    try {
      const parsed = new URL(url);
      this.domain = parsed.hostname;
    } catch {
      this.domain = null;
    }
  }

  static fromEndpoint({ url, method, sitemap, body = null }) {
    const tags = sitemap.getTags(method, url, body);
    return new Action(method, url, body, tags);
  }
}

// -------------------------
// MatchBlock
// -------------------------
class MatchBlock {
  constructor(tags = null) {
    this.tags = tags;
  }

  static fromDict(data) {
    return new MatchBlock(data.tags || null);
  }

  matches(action) {
    if (this.tags) {
      if (!action.tags) return false;
      return this.tags.every(tag => action.tags.includes(tag));
    }
    return true;
  }
}

// -------------------------
// ExceptionBlock
// -------------------------
class ExceptionBlock {
  constructor(match) {
    this.match = match;
  }

  static fromDict(data) {
    if (!("match" in data)) {
      throw new Error("ExceptionBlock must have a 'match' field");
    }
    if (data.match === "*") {
      throw new Error("ExceptionBlock does not support match all.");
    }
    return new ExceptionBlock(MatchBlock.fromDict(data.match));
  }

  matches(action) {
    return this.match.matches(action);
  }
}

// -------------------------
// Rule
// -------------------------
class Rule {
  constructor(effect, match = null, exceptions = null, description = null) {
    this.effect = effect; // "allow", "deny", or "allow_public"
    this.match = match;
    this.exceptions = exceptions;
    this.description = description;
  }

  static fromDict(data) {
    return new Rule(
      data.effect,
      data.match ? MatchBlock.fromDict(data.match) : null,
      data.exceptions ? data.exceptions.map(e => ExceptionBlock.fromDict(e)) : null,
      data.description || null
    );
  }

  appliesTo(action) {
    if (this.match && !this.match.matches(action)) {
      return false;
    }
    if (this.exceptions && this.exceptions.length > 0) {
      if (this.exceptions.some(e => e.matches(action))) {
        return false;
      }
    }
    return true;
  }
}

// -------------------------
// Policy
// -------------------------
class Policy {
  constructor(name, defaultEffect, rules, domains, description = "") {
    this.name = name;
    this.default = defaultEffect; // "allow", "deny", "allow_public"
    this.rules = rules;
    this.domains = domains;
    this.description = description;

    this._postInit();
  }

  _postInit() {
    const ruleEffects = new Set(this.rules.map(r => r.effect));

    if (ruleEffects.has(this.default)) {
      throw new InvalidPolicyError(
        `Invalid policy: default='${this.default}' must not equal any rule effect ${Array.from(ruleEffects)}.`
      );
    }

    if (this.default === "allow_public" && ruleEffects.size > 1) {
      throw new InvalidPolicyError(
        "Invalid policy: if default='allow_public', all rules must have the same effect (all allow OR all deny)."
      );
    }

    if (this.default === "deny") {
      this.rules.sort((a, b) => (a.effect === "allow_public" ? -1 : 1));
    } else if (this.default === "allow") {
      this.rules.sort((a, b) => (a.effect === "deny" ? -1 : 1));
    }
  }

  static fromDict(data) {
    const requiredKeys = ["name", "default", "rules", "domains"];
    for (const key of requiredKeys) {
      if (!(key in data)) {
        throw new Error(`Policy is missing required field: ${key}`);
      }
    }
    if (!data.domains || data.domains.length === 0) {
      throw new Error("Policy must have at least one domain in 'domains'");
    }
    return new Policy(
      data.name,
      data.default,
      data.rules.map(r => Rule.fromDict(r)),
      data.domains,
      data.description || ""
    );
  }

  evaluate(action) {
    if (this.domains !== "*" && !this.domains.some(domain => this._domainMatches(domain, action))) {
      return "deny";
    }
    for (let i = 0; i < this.rules.length; i++) {
      const rule = this.rules[i];
      if (rule.appliesTo(action)) {
        return rule.effect;
      }
    }
    return this.default;
  }

  _domainMatches(domainPattern, action) {
    if (domainPattern.startsWith("*.")) {
      const base = domainPattern.slice(2);
      return action.domain === base || action.domain.endsWith("." + base);
    } else {
      return action.domain === domainPattern;
    }
  }
}

// -------------------------
// SitemapEntry
// -------------------------
class SitemapEntry {
  constructor(method, urlTemplate, regex, tags, semanticAction, body = null) {
    this.method = method;
    this.urlTemplate = urlTemplate;
    this.regex = regex;
    this.tags = tags;
    this.semanticAction = semanticAction;
    this.body = body;
  }

  match(actionMethod, actionUrl, actionBody) {
    if (actionMethod.toUpperCase() !== this.method.toUpperCase()) return false;
    if (!this.regex.test(actionUrl)) return false;
    // TODO: body matching logic if needed
    return true;
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
    let pattern = urlTemplate.replace(/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g, "(?<$1>[^/]+)");
    pattern = pattern.replace(/\*/g, ".*");
    return new RegExp(`^${pattern}$`);
  }

  parseSitemapJson(jsonData) {
    const data = typeof jsonData === "string" ? JSON.parse(jsonData) : jsonData;
    for (const item of data) {
      const urlTemplate = item.url;
      const method = (item.method || "").toUpperCase();
      const tags = item.tags;
      const semanticAction = item.semantic_action || "";
      const body = item.body || {};
      if (!urlTemplate || !method || !Array.isArray(tags)) {
        throw new Error(`Invalid entry: ${JSON.stringify(item)}`);
      }
      const regex = this._compileTemplate(urlTemplate);
      this.entries.push(new SitemapEntry(method, urlTemplate, regex, tags, semanticAction, body));
    }
  }

  getTags(actionMethod, actionUrl, actionBody = {}) {
    const method = actionMethod.toUpperCase();
    for (const entry of this.entries) {
      if (entry.match(method, actionUrl, actionBody)) {
        return entry.tags;
      }
    }
    return [];
  }
}

// -------------------------
// Exports
// -------------------------
export {
  Endpoint,
  Action,
  MatchBlock,
  ExceptionBlock,
  Rule,
  Policy,
  InvalidPolicyError,
  PolicyDenied,
  SitemapEntry,
  Sitemap
};
