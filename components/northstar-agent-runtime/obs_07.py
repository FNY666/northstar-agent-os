"""obs_07: Baggage propagation (mock), Simulated.

Baggage carries tenant/user context across service boundaries.
Mock: in-memory dict, no actual propagation.  Interface matches
W3C Baggage shape (key=value pairs).

Fail-closed: invalid key/value raises.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Dict, Optional

OBS07_VERSION = "obs-07.v1"
SCHEMA_PIN = "northstar.obs-07.v1"


class Obs07Error(Exception):
    """Fail-closed."""


class Baggage:
    """Mock baggage store."""

    def __init__(self) -> None:
        self._items: Dict[str, str] = {}

    def set(self, key: str, value: str) -> None:
        if not isinstance(key, str) or not key:
            raise Obs07Error("key must be non-empty str")
        if not isinstance(value, str):
            raise Obs07Error("value must be str")
        if "=" in key or ";" in key or "," in key:
            raise Obs07Error("key contains reserved chars")
        self._items[key] = value

    def get(self, key: str) -> Optional[str]:
        if not isinstance(key, str):
            raise Obs07Error("key must be str")
        return self._items.get(key)

    def serialize(self) -> str:
        """W3C Baggage header format: k1=v1,k2=v2."""
        return ",".join(f"{k}={v}" for k, v in self._items.items())

    @classmethod
    def deserialize(cls, header: str) -> "Baggage":
        """Parse a baggage header.  Raises on malformed."""
        if not isinstance(header, str):
            raise Obs07Error("header must be str")
        b = cls()
        if not header.strip():
            return b
        for pair in header.split(","):
            if "=" not in pair:
                raise Obs07Error(f"malformed pair '{pair}'")
            k, v = pair.split("=", 1)
            b.set(k.strip(), v.strip())
        return b


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    b = Baggage()
    b.set("tenant", "acme")
    b.set("user", "u123")
    assert b.get("tenant") == "acme"
    h = b.serialize()
    b2 = Baggage.deserialize(h)
    assert b2.get("user") == "u123"
    try:
        b.set("bad=key", "v")
        raise AssertionError("should raise")
    except Obs07Error:
        pass
    assert stdlib_only()
    print("obs_07 OK")


if __name__ == "__main__":
    main()
