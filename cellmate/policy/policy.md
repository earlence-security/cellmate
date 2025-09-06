# 🛡️ Browser Action Policy Language

This document defines a flexible JSON-based policy language for controlling browser UI actions. Policies can be used to **allow or deny specific categories of actions** based on composable tags, with clear support for fine-grained exceptions.

---

## 📦 Policy Overview

Each policy is a JSON object that defines:

- A **short identifier** (`name`)
- A **default effect** (`default`) that applies to all the actions by default
- A **domains** field that defines which domains this policy applies to.
- A list of **explicit rules** that override the default effect.
- Optional **human-readable description** (`description`)

Each rule will include:

- An **effect**, `deny` or `allow` or `allow_public`, that applies to the actions specified in this rule.
- A **match** field that supports rich matching. The supported matching types include:
- Optional **exceptions** to exempt certain actions from matching rules.
- Optional **human-readable description** (`description`)

---

## 🧱 Policy Structure

```json
{
  "name": "read_public_repo",
  "description": "Allows read-only access to unarchived public repository. Denies all other actions.",
  "domains": ["gitlab.com"],
  "default": "deny",
  "rules": [
    {
      "effect": "allow",
      "match": {
        "tags": ["public", "repository", "read", "~archived"]
      },
      "exceptions": {
        "match": {
          "endpoints": [
            { "url": "*/secret-repo" }
          ]
        }
      }
      "description": "Allow read access to public repositories, excluding archived ones and secret repos."
    }
  ]
}
```

---

## 🗂️ Top-Level Fields

| Field         | Type                                      | Required | Description                                                                               |
| ------------- | ----------------------------------------- | -------- | ----------------------------------------------------------------------------------------- |
| `name`        | `str`                                     | ✅       | Name or identifier for the policy. Example: `"read_private_repo"`                         |
| `description` | `string`.                                 | 🔶       | A high-level description of the policy's purpose and intent.                              |
| `default`     | `"allow"` \| `"deny"` \| `"allow_public"` | ✅       | Whether actions are allowed or denied by default.                                         |
| `domains`     | `list[str]` \| `"\*"`                     | ✅       | Domains that this policy applies to. `"*"` indicates the rule applies to all the domains. |
| `rules`       | `list[Rule]`                              | ✅       | Specific allow or deny rules using tags and match logic.                                  |

---

## 📄 Rule Format

Each rule block contains:

| Field         | Type                                      | Description                                                                                 |
| ------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------- |
| `effect`      | `"allow"` \| `"deny"` \| `"allow_public"` | Must be `"allow"` or `"deny"` or `"allow_public"` — and opposite of the top-level `default` |
| `match`       | `Matching` \| `"*"`                       | A set of conditions: `tags`, `urls`, `fields` or literal `"*"`. Details below               |
| `exceptions`  | `list[Matching]`                          | Optional. If any match, the rule is skipped                                                 |
| `description` | `str`                                     | Optional. Human-readable explanation of the rule                                            |

---

## Effect

Effects inside a policy includes `"default"` effect and `"effect"`s in each rule. Values of `"effect"` fields could be `"allow"`, `"deny"` or `"allow_public"`.
If an action is evaluated as `"allow"`, its execution will continue; if an action is evaluated as `"deny"`, it will be blocked; if an action is evaluated as `"allow_public"`, it will be proceeded without authorization header, in order to make sure only public resources are accessed.

---

### 🔹 Lattice View of Effects

Restrictiveness ordering:

```
deny  >  allow_public  >  allow
```

- **`deny`** = most restrictive (blocks the action)
- **`allow_public`** = middle (restricts to public data only)
- **`allow`** = most permissive (allows the action)

> During evaluation, the **most restrictive matching rule wins**.

---

### ⚠️ Rule–Default Consistency

Rules must be **consistent with the `default`**:

| `default`        | Permitted rule effects                       |
| ---------------- | -------------------------------------------- |
| `"allow"`        | `"deny"` or `"allow_public"`                 |
| `"deny"`         | `"allow"` or `"allow_public"`                |
| `"allow_public"` | Either **all `"allow"`** or **all `"deny"`** |

- **`default = "deny"`** → Rules can only **relax restrictions** (move upward to `allow_public` or `allow`).
- **`default = "allow"`** → Rules can only **tighten restrictions** (move downward to `allow_public` or `deny`).
- **`default = "allow_public"`** → Rules must be **uniform**:

  - All `allow` rules → upgrade specific actions from public to private access.
  - All `deny` rules → carve out forbidden actions while keeping the rest public.

✅ These constraints are enforced at policy compilation time.

---

## 🏷️ Action Matching Semantics

Each rule’s `match` block supports **four types** of matching criteria:

---

### 🔹 `"*"`

`"*"` matches all the actions.

### 🔹 `tags`

- `tags` are **arbitrary string labels** derived from **browser semantics**, DOM attributes, or sitemap annotations.
- Matching uses **AND logic**:
  → All listed tags must be present in the action.
- If a tag starts with `~`, it denotes **negation** (i.e., the tag must not be present).
  → For example, `"~archived"` means the action must **not** be tagged as `archived`.
- If `tags` not specified or `"tags": []`, all the action will be matched (within the specified `domains`).

> Tags provide a composable vocabulary for describing **categories of browser behavior**, like `["private", "repository", "read"]`.

---

### 🔹 `endpoints`

- Enables matching **URL and HTTP method** combinations.
- Each entry must contain:

  - `"method"`: HTTP method (e.g., `GET`, `POST`, `PUT`)
  - `"url"`: URL string (wildcards like `*` supported)

```json
"endpoints": [
  { "method": "POST", "url": "https://gitlab.com/*/deploy_token/create" }
]
```

→ Matches a `POST` to that path.

---

### 🔹 `fields`

- `fields` describe **variable-value pairs** extracted from the action, for example, the data fields in form submission.
- This enables **parameterized matching**, such as:

  - Repository names
  - Usernames
  - Form input values

- You can match all actions where a field has a specific value — for example:

  ```json
  "match": {
    "fields": {
      "owner": "alice"
    }
  }
  ```

> This allows matching a class of actions tied to dynamic values like ownership, input, or selection.

### ❗ Matching Logic

#### ✅ Within a `match` block: **AND logic**

All specified conditions (`tags`, `fields`, `url`, etc.) must be satisfied.

#### ✅ Across multiple `match` blocks (e.g., in `exceptions`): **OR logic**

In the following example, AND logic applies to the `"tags"` and `"endpoints"` inside rule matching, and OR logic applies to the two matching blocks under `"exceptions"`.

```json
{
  "name": "read_public_repo",
  "description": "Allows read-only access to unarchived public repository. Denies all other actions.",
  "domains": ["gitlab.com"],
  "default": "deny",
  "rules": [
    {
      "effect": "allow",
      "match": {
        "tags": ["public", "repository", "read"],
        "endpoints": [
          {
            "method": "GET",
            "url": "https://gitlab.com/Rosie-m/*"
          }
        ]
      },
      "exceptions": {
        "match": {
          "endpoints": [
            { "url": "*/secret-repo" }
          ]
        },
        "match": {
          "tags": ["~archived"]
        }
      }
      "description": "Allow read access to public repositories belong to 'Rosie-m', excluding archived ones and secret repos."
    }
  ]
}
```

If **any** exception block matches, the rule is skipped.

---

## ❗ Exceptions

If an action matches a rule but also matches **any exception**, the rule is skipped.

```json
"exceptions": [
  {
    "match": {
      "repo_name": "hello-world"
    }
  },
  {
    "match": {
      "endpoints": [
        {
          "url": "https://github.com/*/special-case-repo",
          "method": "GET",
        }
      ]
    }
  }
]
```

---

## ⚙️ Evaluation Model

```pgsql
         ┌─────────────────────┐
         │   Action arrives    │
         └─────────┬───────────┘
                   │
                   ▼
    ┌─────────────────────────────┐
    │ Is action domain covered?   │
    └─────────┬────────────┬──────┘
              │            │
             Yes           No
              │            │
              ▼            ▼
    ┌────────────────┐   ┌─────────┐
    │ Check rules    │   │ DENY    │
    │ applicability  │   └─────────┘
    └─────────┬──────┘
              │
              ▼
    ┌───────────────────────────────┐
    │ Any rules match?              │
    └─────────┬───────────────┬─────┘
              │               │
             Yes              No
              │               │
              ▼               ▼
    ┌──────────────────┐  ┌──────────────┐
    │ Apply most       │  │ DEFAULT      │
    │ restrictive rule │  │ EFFECT       │
    └──────────────────┘  └──────────────┘
```

1. **Domain Check**: If the action’s domain is outside the policy, it is denied.
2. **Rule Matching**: Identify all rules that apply to the action.
3. **Effect Resolution**: If multiple rules match, the **most restrictive effect wins** (`deny` > `allow_public` > `allow`).
4. **Default**: If no rules match, the policy’s default effect applies.

This ensures that actions are allowed only when explicitly permitted and that restrictive rules take precedence.

---

## 📘 Example Policies

### ✅ Deny all actions on private repositories

```json
{
  "name": "deny_private_repos",
  "description": "Blocks all actions involving private repositories on GitLab or GitHub.",
  "default": "allow",
  "domains": ["gitlab.com", "github.com"],
  "rules": [
    {
      "effect": "deny",
      "match": {
        "tags": ["private", "repository"]
      },
      "description": "No access to private repositories."
    }
  ]
}
```

---

### ✅ Allow only one private repo (deny-all baseline)

```json
{
  "name": "allow_hello_world_only",
  "description": "Allow public resource and read access to private repos on GitLab",
  "default": "deny",
  "domains": ["gitlab.com"],
  "rules": [
    {
      "effect": "allow",
      "match": {
        "tags": ["read", "repository"]
      },
      "description": "Allow read access to user's private repository"
    },
    {
      "effect": "allow_public",
      "match": "*",
      "description": "Allow access to all public resources on GitLab"
    }
  ]
}
```

### ✅ Allow read access to all private repos except specific sensitive ones

```json
{
  "name": "allow_private_repo_read_with_exceptions",
  "description": "Allows read access to private repositories, but blocks sensitive or deprecated ones.",
  "domains": ["gitlab.com"],
  "default": "deny",
  "rules": [
    {
      "effect": "allow",
      "match": {
        "tags": ["private", "repository", "read", "~archived"]
      },
      "exceptions": [
        {
          "match": {
            "fields": {
              "repo_name": "secret-internal-repo"
            }
          }
        },
        {
          "match": {
            "tags": ["deprecated"]
          }
        },
        {
          "match": {
            "url": "https://github.com/myorg/do-not-read"
          }
        }
      ],
      "description": "Allow private repo reads unless the repo is deprecated, explicitly blocked, or highly sensitive."
    }
  ]
}
```

---

## 🧠 Best Practices

- Use consistent and semantically meaningful **tags**
- Use `~tag` negation for exclusion without complex conditionals
- Keep rules composable and small for reusability
- Prefer `default: "deny"` for security-critical agents
- Use `description` on both policy and rules for maintainability

---

## 🔮 Possible Extensions

- Add `conditions` for time of day, user roles, or agent types
- Support `log`, `warn_only`, or `dry_run` effects
- Allow reusable tag groups or hierarchy definitions
- Add policy inheritance or composition mechanisms

---
