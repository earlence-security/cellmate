# 🗺️ Sitemap Specification

The **sitemap** defines how browser or system actions are recognized, and how contextual data is extracted for authorization or analysis.
Each entry provides a **semantic mapping** from low-level web behavior (network requests, DOM events) to a high-level **action** (e.g., `place_order`, `cancel_order`, `post_comment`).

---

## 🧩 Sitemap Entry Schema

Each sitemap entry follows this structure:

```json
{
  "semantic_action": "string",
  "url": "string",
  "method": "string",
  "args": {
    "<arg_name>": {
      "type": "string",
      "source": {
        "type": "string",
        "...": "type-specific fields"
      }
    }
  }
}
```

---

## 🔖 Top-Level Fields

| Field                 | Type     | Required | Description                                                                                                             |
| --------------------- | -------- | -------- | ----------------------------------------------------------------------------------------------------------------------- |
| **`semantic_action`** | `string` | ✅       | Domain-agnostic name of the action being performed (e.g., `place_order`, `cancel_order`). Used in policy definitions.   |
| **`url`**             | `string` | ✅       | URL pattern (supports wildcards) that matches the network request triggering this action.                               |
| **`method`**          | `string` | ✅       | HTTP method associated with the action (`GET`, `POST`, `PUT`, etc.).                                                    |
| **`args`**            | `object` | ❌       | Map of named contextual arguments extracted from the page or request. Each argument specifies a type and a data source. |

---

## ⚙️ Argument Definition

Each argument entry defines:

- The argument’s **data type**, and
- A **source object** describing how to extract its value.

### Common fields

| Field        | Type     | Description                                                                                           |
| ------------ | -------- | ----------------------------------------------------------------------------------------------------- |
| **`type`**   | `string` | Data type (`string`, `number`, `boolean`, etc.). Used for validation and type coercion.               |
| **`source`** | `object` | Defines where and how to extract the argument value. The structure of `source` depends on its `type`. |

---

## 🧱 Source Types

### 1️⃣ `source.type = "dom"`

Used when the value should be read from the web page’s DOM.

```json
"source": {
  "type": "dom",
  "url": "https://www.example.com/checkout/*",
  "selector": "#total-price"
}
```

| Field          | Type     | Required | Description                                                         |
| -------------- | -------- | -------- | ------------------------------------------------------------------- |
| **`type`**     | `"dom"`  | ✅       | Indicates the argument value should be extracted from the page DOM. |
| **`url`**      | `string` | ✅       | Page URL pattern where the DOM selector applies.                    |
| **`selector`** | `string` | ✅       | CSS selector identifying the element containing the argument value. |

---

### 2️⃣ `source.type = "request_body"`

Used when the value should be parsed from the HTTP request body.

```json
"source": {
  "type": "request_body",
  "url": "https://api.example.com/v1/order",
  "json_key": "totalAmount"
}
```

| Field          | Type             | Required | Description                                                                   |
| -------------- | ---------------- | -------- | ----------------------------------------------------------------------------- |
| **`type`**     | `"request_body"` | ✅       | Indicates the argument value should be extracted from a network request body. |
| **`url`**      | `string`         | ✅       | The request URL (or pattern) from which to extract the value.                 |
| **`json_key`** | `string`         | ✅       | JSON key path (dot-notation supported) specifying which field to read.        |

Example:
If the request body is:

```json
{
  "order": { "totalAmount": 49.99 }
}
```

and `json_key = "order.totalAmount"`, the extracted value will be `49.99`.

---

## 🧠 Example Sitemap Entry

```json
{
  "semantic_action": "place_order",
  "url": "https://www.amazon.com/checkout/p/*/spc/place-order*",
  "method": "POST",
  "args": {
    "total_amount": {
      "type": "number",
      "source": {
        "type": "dom",
        "url": "https://www.amazon.com/checkout/p/*",
        "selector": "#subtotals-marketplace-table li:nth-child(4) .order-summary-line-definition"
      }
    }
  }
}
```

Alternate form (if total amount comes from API payload instead of DOM):

```json
{
  "semantic_action": "place_order",
  "url": "https://api.amazon.com/checkout/place-order",
  "method": "POST",
  "args": {
    "total_amount": {
      "type": "number",
      "source": {
        "type": "request_body",
        "url": "https://api.amazon.com/checkout/place-order",
        "json_key": "order.totalAmount"
      }
    }
  }
}
```

---

## 🔐 Role in Policy Evaluation

At runtime:

1. The system intercepts network requests matching the sitemap’s `url` and `method`.
2. For each matching action, it collects arguments using the described sources:

   - `dom` → read from visible page content.
   - `request_body` → parse from outgoing JSON payload.

3. It constructs a semantic action object, e.g.:

   ```json
   {
     "action": "place_order",
     "context": { "total_amount": 49.99 }
   }
   ```

4. This context is passed to the policy engine for enforcement.

---

## 💡 Why We Need Sitemap

- Ease policy writing. Without a sitemap, writing each policy requires _translating high-level intension to low-level enforcement;_ with a sitemap, it can be reused for all the policies.
- Policy remains semantic and durable. If the request syntax or page DOM is changed, only needs to update sitemap; policies are still valid and meaningful.
- Enforcement is transparent. Enables third-party (e.g., administrators, advanced users, or our policy predictor) to predict/create policies when needed.
- Defines the boundary of “security-relevant” actions. Only actions in sitemap are policy-controlled, others default to allow.

## 💡 Design Notes

- The **typed source model** keeps extraction logic declarative and consistent across domains.
- New source types (e.g., `"header"`, `"cookie"`, `"storage"`) can be added in the same format without breaking compatibility.
