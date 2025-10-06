"""
Policy module for handling browser actions and requests.

09/16/2025: Updates:
    -  TODO

08/28/2025: Note:
    - We updated the Policy syntax for DeclarativeNetRequest rule generation. Those changes have NOT been reflected in this file.

08/19/2025: Updates:
    - Added support for handling request body. Enabled matching request body for GraphQL requests.
    - Improved domain and request matching with wildcard (`'*'`) support that matches all.
    - Renamed `"allowed_domains"` to `"domains"` in `Policy` class.
"""

import re
import json
import email
import logging
import urllib.parse


from dataclasses import dataclass
from typing import Literal, Any
from urllib.parse import urlparse
from email.utils import collapse_rfc2231_value
from playwright.async_api import Request
from .sitemap import Sitemap
from .state import StateStore, StateInfoBlock

logger = logging.getLogger(__name__)


@dataclass
class Endpoint:
    url: str
    method: str | None = None

    def matches(self, action_endpoint: 'Endpoint') -> bool:
        """
        Check if this endpoint matches the action's endpoint.
        URL can contain wildcards like '*'.
        Method is optional and case-insensitive.
        """
        # Compare HTTP methods if specified
        if self.method and (action_endpoint.method is None or self.method.upper() != action_endpoint.method.upper()):
            return False

        # Convert wildcard URL to regex
        url_pattern = re.escape(self.url).replace(r'\*', '.*')
        pattern = re.compile(f"^{url_pattern}$")

        return bool(pattern.match(action_endpoint.url))


@dataclass
class Action:
    endpoint: Endpoint
    domain: str
    tags: list[str] | None = None
    body: dict[str, Any] | None = None

    @staticmethod
    def from_request(request: "Request", sitemap: "Sitemap") -> "Action":
        raw_body = request.post_data
        content_type = request.headers.get("content-type", "").lower()
        body: dict[str, Any] = {}

        if raw_body is not None:
            if "application/json" in content_type:
                try:
                    if isinstance(raw_body, bytes):
                        raw_body = raw_body.decode(errors="ignore")
                    body = json.loads(raw_body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    body = {"_raw": raw_body if isinstance(raw_body, bytes) else raw_body.encode()}
            
            elif "application/x-www-form-urlencoded" in content_type:
                if isinstance(raw_body, bytes):
                    raw_body = raw_body.decode(errors="ignore")
                body = dict(urllib.parse.parse_qsl(raw_body))
            
            elif "multipart/form-data" in content_type:
                msg = email.message_from_bytes(
                    raw_body.encode() if isinstance(raw_body, str) else raw_body
                )
                for part in msg.walk():
                    if part.get_content_disposition() == "form-data":
                        name_param = part.get_param("name", header="content-disposition")
                        name = collapse_rfc2231_value(name_param) if name_param else None
                        if not name:
                            continue
                        filename = part.get_filename()
                        payload = part.get_payload(decode=True)
                        if filename:
                            body[name] = {
                                "filename": filename,
                                "content_type": part.get_content_type(),
                                "content": payload if isinstance(payload, bytes) else str(payload)
                            }
                        else:
                            if isinstance(payload, bytes):
                                try:
                                    body[name] = payload.decode(errors="ignore")
                                except UnicodeDecodeError:
                                    body[name] = payload  # keep raw bytes
                            else:
                                body[name] = str(payload)

            else:
                # Unknown content type -> store raw body
                body["_raw"] = raw_body if isinstance(raw_body, bytes) else raw_body.encode()

        return Action(
            endpoint=Endpoint(url=request.url, method=request.method),
            domain=urlparse(request.url).netloc,
            tags=sitemap.get_tags(request.method, request.url, body),
            body=body
        )

    @staticmethod
    def from_endpoint(url: str, method: str, sitemap: Sitemap | None = None, body: dict[str, Any] = {}) -> "Action":
        """
        Create an Action from an endpoint. This is only used for testing purposes.
        """
        parsed_url = urlparse(url)
        if not sitemap:
            return Action(
                endpoint=Endpoint(url=url, method=method),
                domain=parsed_url.netloc,
                tags=[],
                body=body
            )
        return Action(
            endpoint=Endpoint(url=url, method=method),
            domain=parsed_url.netloc,
            tags=sitemap.get_tags(method, url, body),
            body=body
        )


@dataclass
class Condition:
    """
    Check values stored in StateStore (the “current state”). Currently only support simple comparisons.
    Will be extended to support more complex conditions or program execution in the future.
    NOTE: Currently, conditions are ANDed together in MatchBlock.
    """
    field: str
    operator: Literal["<=", "<", ">=", ">", "==", "!="]
    value: Any

    @staticmethod
    def from_dict(data: dict) -> "Condition":
        required = ["field", "operator", "value"]
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(f"Condition is missing required fields: {', '.join(missing)}")
        return Condition(
            field=data["field"],
            operator=data["operator"],
            value=data["value"]
        )

    def evaluate(self, state: StateStore | None = None) -> bool:
        """Evaluate this condition against the current state dict."""
        if state is None:
            return False
        field_val = state.get(self.field)
        if field_val is None:
            return False

        try:
            if self.operator == "<=":
                return field_val <= self.value
            elif self.operator == "<":
                return field_val < self.value
            elif self.operator == ">=":
                return field_val >= self.value
            elif self.operator == ">":
                return field_val > self.value
            elif self.operator == "==":
                return field_val == self.value
            elif self.operator == "!=":
                return field_val != self.value
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Condition evaluation error: {e}")
            return False
        return False


@dataclass
class MatchBlock:
    tags: list[str] | None = None
    endpoints: list[Endpoint] | None = None
    conditions: list[Condition] | None = None
    match_all: bool = False  # If True, matches all actions regardless of tags or endpoints


    @staticmethod
    def from_dict(data: dict | str) -> "MatchBlock":
        if isinstance(data, dict):
            return MatchBlock(
                tags=data.get("tags"),
                endpoints=[
                    Endpoint(url=e.get("url"), method=e.get("method"))
                    for e in data.get("endpoints", [])
                ],
                conditions=[Condition.from_dict(c) for c in data.get("conditions", [])],
                match_all=False
            )
        else:
            if data == '*':
                return MatchBlock(match_all=True)
            else:
                raise ValueError("MatchBlock not supported. Must be literal '*' or a dictionary.")

    def matches(self, action: Action, state: StateStore | None = None) -> bool:
        # '*': Match all actions if match_all is True
        logger.debug(f"⏳ Matching action: {action.endpoint.method} {action.endpoint.url} with tags: {action.tags}")
        if self.match_all:
            return True
        # Tags: AND logic, negation with ~
        if self.tags and not action.tags:
            return False
        if self.tags and action.tags:
            for tag in self.tags:
                if tag.startswith("~"):
                    if tag[1:] in action.tags:
                        return False
                else:
                    if tag not in action.tags:
                        return False

        # Endpoints: match one or more patterns
        # TODO: Is it safe to do wildcard matching here?
        if self.endpoints:
            action_endpoint = action.endpoint
            if not any(
                pattern.matches(action_endpoint)
                for pattern in self.endpoints
            ):
                return False

        # Conditions: AND semantics by default
        if self.conditions and state:
            for cond in self.conditions:
                if not cond.evaluate(state):
                    return False
        logger.debug(f"🎯 Matched tags: {self.tags} with action tags: {action.tags}")
        return True


@dataclass
class ExceptionBlock:
    match: MatchBlock

    @staticmethod
    def from_dict(data: dict) -> "ExceptionBlock":
        assert "match" in data, "ExceptionBlock must have a 'match' field"
        if data.get("match") == '*':
            raise ValueError("ExceptionBlock does not support match all.")
        return ExceptionBlock(
            match=MatchBlock.from_dict(data["match"])
        )

    def matches(self, action: Action) -> bool:
        return self.match.matches(action)


@dataclass
class Rule:
    effect: Literal['allow', 'deny', 'allow_public']
    match: MatchBlock | None = None
    exceptions: list[ExceptionBlock] | None = None
    description: str | None = None
    state_info: list[StateInfoBlock] | None = None

    @staticmethod
    def from_dict(data: dict) -> "Rule":
        return Rule(
            effect=data["effect"],
            match=MatchBlock.from_dict(data["match"]) if "match" in data else None,
            exceptions=[
                ExceptionBlock.from_dict(e)
                for e in data.get("exceptions", [])
            ] if "exceptions" in data else None,
            description=data.get("description")
        )

    def applies_to(self, action: Action, state: StateStore | None = None) -> bool:
        # Match check
        if self.match and not self.match.matches(action, state):
            return False
        # Exception check (OR logic)
        if self.exceptions and any(e.matches(action, state) for e in self.exceptions):
                return False
        return True


@dataclass
class Policy:
    name: str
    default: Literal['allow', 'deny', 'allow_public']
    rules: list[Rule]
    domains: list[str] | Literal['*']
    description: str = ""

    def __post_init__(self):
        """
        Validate and normalize a Policy after initialization.

        Checks:
        1. Default vs. rule consistency:
        - The default effect must not be identical to any rule effect.
        - If default = "allow_public", all rules must have the same effect 
            (either all "allow" or all "deny").
        2. Rule ordering for deterministic evaluation:
        - If default = "deny": sort rules so that "allow_public" rules come before "allow".
        - If default = "allow": sort rules so that "deny" rules come before "allow_public".
        - If default = "allow_public": keep rule order (uniformity already enforced).
        """
        rule_effects = {r.effect for r in self.rules}

        # (1) Consistency checks
        if self.default in rule_effects:
            raise InvalidPolicyError(
                f"Invalid policy: default='{self.default}' "
                f"must not equal any rule effect {rule_effects}."
            )

        if self.default == "allow_public" and len(rule_effects) > 1:
            raise InvalidPolicyError(
                "Invalid policy: if default='allow_public', "
                "all rules must have the same effect (all allow OR all deny)."
            )

        # (2) Sorting: more restrictive rules first
        if self.default == "deny":
            # allow_public rules first, then allow rules
            self.rules.sort(key=lambda r: 0 if r.effect == "allow_public" else 1)
        elif self.default == "allow":
            # deny rules first, then allow_public rules
            self.rules.sort(key=lambda r: 0 if r.effect == "deny" else 1)
        # if default == "allow_public", order stays as-is

    @staticmethod
    def from_json(json_data: str) -> "Policy":
        data = json.loads(json_data)
        return Policy.from_dict(data)

    @staticmethod
    def from_dict(data: dict) -> "Policy":
        required_keys = ["name", "default", "rules", "domains"]
        missing = [k for k in required_keys if k not in data]
        if missing:
            raise ValueError(f"Policy is missing required fields: {', '.join(missing)}")
        if not data["domains"]:
            raise ValueError("Policy must have at least one domain in 'domains' field")
        return Policy(
            name=data["name"],
            description=data.get("description", ""),
            default=data["default"],
            rules=[Rule.from_dict(r) for r in data["rules"]],
            domains=data["domains"]
        )

    def evaluate(self, action: Action, state_store: StateStore | None = None) -> str:
        """
        Evaluate the policy against a given action.
        1. If the policy does not apply to the action, i.e., action domain outside the policy's domains, return "deny".
        2. If find a matching rule, return its effect.
        3. If no rules match, return the default effect.
        """
        if state_store is None:
            state_store = StateStore()  # initialize empty state

        # Load state_info from all rules into state_store
        for rule in self.rules:
            if rule.state_info:
                for info_block in rule.state_info:
                    state_store.register_state_info(info_block)

        # Domain check
        if self.domains != '*' and not any(self._domain_matches(domain, action) for domain in self.domains):
            return "deny"
        # `__post_init__` already sorts rules so that the most restrictive ones come first.
        for i, rule in enumerate(self.rules):
            if rule.applies_to(action, state):
                logger.debug(f"🔍 Evaluating against rule #{i}.")
                return rule.effect
        return self.default
    
    def _domain_matches(self, domain_pattern: str, action: Action) -> bool:
        """
        Check if the action's domain matches any allowed domains.
        """
        if domain_pattern.startswith("*."):
            base = domain_pattern[2:]
            return action.domain == base or action.domain.endswith("." + base)
        else:
            return action.domain == domain_pattern


class InvalidPolicyError(Exception):
    """
    Custom exception for policy violations.
    This exception is raised when an action is not allowed by the policy.
    """
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return f"InvalidPolicyError: {self.message}."


class PolicyDenied(Exception):
    """
    Custom exception for policy evaluation failures.
    This exception is raised when the policy evaluation fails unexpectedly.
    """
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

    def __str__(self):
        return f"PolicyDenied: {self.message}. Agent MUST terminate the task immediately, not retry it."
