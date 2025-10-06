# state.py
from dataclasses import dataclass
from typing import Any, Literal

@dataclass
class Endpoint:
    url: str
    method: str | None = None

@dataclass
class StateSource:
    endpoint: Endpoint
    from_: Literal["request", "response"]
    source_type: Literal["html", "json", "text"]
    path: str | None = None  # XPath, JSONPath, or key path

@dataclass
class StateInfoBlock:
    field: str
    type: Literal["number", "string", "boolean"]
    sources: list[StateSource]

    @staticmethod
    def from_dict(field: str, data: dict) -> "StateInfoBlock":
        return StateInfoBlock(
            field=field,
            type=data["type"],
            sources=[
                StateSource(
                    endpoint=Endpoint(
                        url=src["endpoint"]["url"],
                        method=src["endpoint"]["method"]
                    ),
                    from_=src["from"],
                    source_type=src["source_type"],
                    path=src.get("path")
                )
                for src in data["sources"]
            ]
        )

class StateStore:
    """
    Keeps track of current state values extracted from responses.
    """
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._data: dict[str, Any] = {}
        self._state_info: list[StateInfoBlock] = []

    def set(self, key: str, value: Any) -> None:
        if self.enabled:
            self.data[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default) if self.enabled else default

    def clear(self) -> None:
        self.data.clear()

    def register_state_info(self, state_info_blocks: list["StateInfoBlock"]) -> None:
        """
        Register a list of StateInfoBlocks. This initializes
        the fields in the state store with default values based on their type.
        """
        if not self.enabled:
            return

        for sib in state_info_blocks:
            if sib.field in [s.field for s in self._state_info]:
                continue  # already registered
            self._state_info.append(sib)

            if sib.type == "number":
                self._data[sib.field] = 0
            elif sib.type == "string":
                self._data[sib.field] = ""
            elif sib.type == "boolean":
                self._data[sib.field] = False
            else:
                self._data[sib.field] = None  # fallback for unknown types

            self.registered_fields.add(sib.field)

    def update_from_response(self, response_content: str):
        """
        Given a response (HTML/JSON/text), update the state store using
        the defined StateInfoBlocks.
        """
        from lxml import html
        import json

        for sib in self._state_info:
            for src in sib.sources:
                if src.from_ != "response":
                    continue
                if src.source_type == "html" and src.path:
                    tree = html.fromstring(response_content)
                    val = tree.xpath(src.path)
                    if val:
                        try:
                            if sib.type == "number":
                                self.set(sib.field, float(val[0].text_content()))
                            elif sib.type == "string":
                                self.set(sib.field, str(val[0].text_content()))
                            elif sib.type == "boolean":
                                text = val[0].text_content().strip().lower()
                                self.set(sib.field, text in ["true", "1"])
                        except Exception as e:
                            # Log and skip on parsing error
                            import logging
                            logging.getLogger(__name__).warning(
                                f"Failed to parse field '{sib.field}' from response: {e}"
                            )
                elif src.source_type == "json" and src.path:
                    try:
                        data = json.loads(response_content)
                        # very basic JSONPath support: dot-separated
                        keys = src.path.split(".")
                        val = data
                        for k in keys:
                            val = val[k]
                        self.set(sib.field, val)
                    except Exception as e:
                        import logging
                        logging.getLogger(__name__).warning(
                            f"Failed to parse JSON field '{sib.field}' from response: {e}"
                        )
                elif src.source_type == "text":
                    # raw text -> store as-is
                    self.set(sib.field, response_content)
