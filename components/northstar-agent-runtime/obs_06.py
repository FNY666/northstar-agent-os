"""obs_06: Span attributes (key-value), Simulated.

Spans carry typed key-value attributes.  Values limited to
str/int/float/bool for serialization safety.

Fail-closed: invalid key/value raises.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Any, Dict

OBS06_VERSION = "obs-06.v1"
SCHEMA_PIN = "northstar.obs-06.v1"


class Obs06Error(Exception):
    """Fail-closed."""


_ALLOWED_TYPES = (str, int, float, bool)


class Span:
    """A trace span with attributes."""

    def __init__(self, name: str, trace_id: str = "") -> None:
        if not name or not isinstance(name, str):
            raise Obs06Error("name must be non-empty str")
        self._name = name
        self._trace_id = trace_id
        self._attrs: Dict[str, Any] = {}

    def set_attribute(self, key: str, value: Any) -> None:
        """Set one attribute.  Raises on invalid."""
        if not isinstance(key, str) or not key:
            raise Obs06Error("key must be non-empty str")
        # bool is subclass of int; allow explicitly.
        if not isinstance(value, _ALLOWED_TYPES):
            raise Obs06Error(f"value for '{key}' must be str/int/float/bool")
        if isinstance(value, float):
            # Reject NaN/inf (not JSON-safe).
            import math
            if not math.isfinite(value):
                raise Obs06Error(f"value for '{key}' must be finite")
        self._attrs[key] = value

    def attributes(self) -> Dict[str, Any]:
        return dict(self._attrs)

    @property
    def name(self) -> str:
        return self._name


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "math", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    s = Span("my-op", "tid123")
    s.set_attribute("http.method", "GET")
    s.set_attribute("http.status", 200)
    s.set_attribute("ratio", 0.5)
    s.set_attribute("cached", True)
    assert s.attributes()["http.method"] == "GET"
    try:
        s.set_attribute("bad", [1, 2])  # type: ignore
        raise AssertionError("should raise")
    except Obs06Error:
        pass
    try:
        s.set_attribute("", "x")
        raise AssertionError("should raise")
    except Obs06Error:
        pass
    assert stdlib_only()
    print("obs_06 OK")


if __name__ == "__main__":
    main()
