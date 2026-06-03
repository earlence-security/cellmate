"""
Sitemap maps browser actions to semantic meanings.
"""
import json
import re

from dataclasses import dataclass

@dataclass
class SitemapEntry:
    method: str
    url_template: str
    regex: re.Pattern
    tags: list[str]
    semantic_action: str
    body: dict | None = None

    def match(self, action_method: str, action_url, action_body: dict | None) -> bool:
        """
        Check if the (method, url) matches this entry.
        Returns True if a match is found, otherwise False.
        """
        if action_method.upper() != self.method.upper():
            return False
        if not self.regex.match(action_url):
            return False
        if self.body:
            if not action_body:
                return False
            if not self._match_dict(self.body, action_body):
                return False
        return True

    def _match_dict(self, pattern: dict, target: dict) -> bool:
        """
        Recursively check if all key-value pairs in pattern exist in target.
        """
        for key, value in pattern.items():
            if key not in target:
                return False
            if isinstance(value, dict):
                if not isinstance(target[key], dict):
                    return False
                if not self._match_dict(value, target[key]):
                    return False
            else:
                if target[key] != value:
                    return False
        return True


class Sitemap:
    def __init__(self, json_data: str | list | None = None):
        # Each entry is (method, url_template_str, compiled_regex, tags)
        self._entries: list[SitemapEntry] = []
        if json_data:
            self.parse_sitemap_json(json_data)

    def _compile_template(self, url_template: str) -> re.Pattern:
        """
        Convert URL template like /groups/{group_name} to regex pattern with named groups.
        """
        pattern = re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", r"(?P<\1>[^/]+)", url_template)
        pattern = pattern.replace("*", ".*")
        return re.compile(f"^{pattern}$")

    def parse_sitemap_json(self, json_data: str | list):
        """
        Parse JSON sitemap and compile templates into regex.
        """
        try:
            if isinstance(json_data, str):
                data = json.loads(json_data)
            else:
                data = json_data
            for item in data:
                url_template = item.get("url")
                method = item.get("method", "").upper()
                tags = item.get("tags")
                semantic_action = item.get("semantic_action", "")
                body = item.get("body", {})
                if not (url_template and method and isinstance(tags, list)):
                    raise ValueError(f"Invalid entry: {item}")
                regex = self._compile_template(url_template)
                self._entries.append(SitemapEntry(method, url_template, regex, tags, semantic_action, body))
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")
        

    def get_tags(self, action_method: str, action_url: str, action_body: dict = {}) -> list[str]:
        """
        Return tags for the first matching (method, url, [body]).
        If no match, returns [].
        """
        # TODO: Use prefix tree to optimize matching
        method = action_method.upper()
        for entry in self._entries:
            if entry.match(method, action_url, action_body):
                return entry.tags
        return []
