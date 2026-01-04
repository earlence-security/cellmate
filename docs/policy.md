# 🧩 Policy Specification

## Overview

A **policy** defines what is **allowed** or **denied** over the semantic actions described in the **sitemap**.
Policies are expressed in a **semantic form**, focusing on user intent rather than low-level enforcement details.

Each policy specifies:

- The **effect** (`allow` or `deny`)
- The **target actions** (as a list, defined in the sitemap)
- An optional **condition** that constrains when the policy applies
- A **description** for human readability

This abstraction enables consistent, interpretable, and user-configurable enforcement across dynamic web environments.

---

## 📦 Structure

| Field                    | Type             | Description                                                    |
| ------------------------ | ---------------- | -------------------------------------------------------------- |
| `effect`                 | string           | The decision outcome (`allow` or `deny`).                      |
| `action`                 | array of strings | One or more semantic actions to which this policy applies.     |
| `condition` _(optional)_ | object           | A predicate that must hold true for the policy to take effect. |
| `description`            | string           | Human-readable explanation of the policy.                      |

---

## ⚙️ Example

```json
{
  "effect": "allow",
  "action": ["place_order"],
  "condition": {
    "name": "amazon_allow_purchase_if_amount_leq",
    "args": ["total_amount"],
    "parameters": {
      "max_amount": 50
    }
  },
  "description": "Allow purchase if total amount is less than or equal to $50"
}
```

### Meaning

This policy allows the `place_order` action **only if** the total purchase amount is ≤ $50.

At runtime, the system evaluates the `condition` using contextual data extracted from the sitemap (e.g., `total_amount`).

---

## 🧠 Condition Object

A `condition` defines a logical predicate evaluated at runtime.
It typically depends on arguments defined in the corresponding sitemap action.

| Field        | Type   | Description                                              |
| ------------ | ------ | -------------------------------------------------------- |
| `name`       | string | Unique identifier of the condition function.             |
| `args`       | array  | Names of arguments (from sitemap) used in the condition. |
| `parameters` | object | Configurable parameters that tune the condition’s logic. |

### Example

```json
"condition": {
  "name": "amazon_allow_purchase_if_amount_leq",
  "args": ["total_amount"],
  "parameters": {
    "max_amount": 50
  }
}
```

This evaluates whether `total_amount ≤ 50`.

---

## 🚧 Design Constraint: Single-Action Condition Rule

- `action` is always a **list**, e.g., `["place_order"]`.
- **If a `condition` is present, the list must contain exactly one action.**

✅ **Allowed**

```json
{
  "action": ["place_order"],
  "condition": { ... }
}
```

❌ **Not allowed**

```json
{
  "action": ["place_order", "checkout_shopping_cart"],
  "condition": { ... }
}
```

**Rationale:**

- Condition arguments (e.g., `total_amount`) are action-specific.
- Multiple actions would make argument context ambiguous.
- Ensures every conditional policy is **unambiguous** and **safe to evaluate**.

Multiple actions **without conditions** are allowed for unconditional allow/deny policies.

---

## ⚙️ Runtime Evaluation Flow

1. **Match:** Find policies that include the observed semantic action.
2. **Check condition (if present):**

   - Only one action is allowed.
   - Extract arguments from the sitemap context.
   - Evaluate the predicate using its parameters.

3. **Apply effect:** `allow` or `deny` according to the policy.

---

## 🔧 Parameterization

- Each `condition` can have **parameters** configured by the user.
- Example: `"max_amount": 3` can be changed to 10 or 50 without modifying policy structure.
- Enables reusable and customizable policy templates.

---

## ✅ Benefits Summary

| Benefit              | Description                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------ |
| **Semantic clarity** | Policies refer to abstract actions, not low-level URLs or DOMs.                            |
| **Durable**          | Policy logic survives changes to DOM or request structure; only sitemap may need updating. |
| **Configurable**     | Parameters allow user-specific tuning.                                                     |
| **Sound**            | Single-action condition rule avoids ambiguity.                                             |
| **Reusability**      | Works with any site having corresponding sitemap definitions.                              |

---
