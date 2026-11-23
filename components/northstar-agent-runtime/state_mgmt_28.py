"""State 28: LWW-map CRDT.

Map where each key holds a last-write-wins register:
- put(key, value, timestamp, node): per-key LWW
- remove(key, timestamp, node): tombstone with an LWW stamp; a later
  put resurrects the key
- get(key): value or KeyError if absent/tombstoned
- merge(other): per-key LWW merge of values and tombstones

Converges without coordination; timestamp ties break on node id.

Fail-closed: empty keys, negative timestamps, empty node raise.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, Optional, Tuple


MODULE_VERSION = "state-mgmt-28.v1"
SCHEMA_PIN = "northstar.state-mgmt-28.v1"


class LWWMapError(Exception):
    pass


Stamp = Tuple[int, str]  # (timestamp, node)


def _check_stamp(timestamp: int, node: str) -> Stamp:
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
        raise LWWMapError("timestamp must be non-negative int")
    if not node:
        raise LWWMapError("node required")
    return (timestamp, node)


class LWWMap:
    def __init__(self) -> None:
        self._values: Dict[str, Tuple[Any, Stamp]] = {}
        self._tombstones: Dict[str, Stamp] = {}

    def put(self, key: str, value: Any, timestamp: int, node: str) -> bool:
        if not isinstance(key, str) or not key:
            raise LWWMapError("key must be non-empty str")
        stamp = _check_stamp(timestamp, node)
        cur = self._values.get(key)
        if cur is not None and cur[1] >= stamp:
            return False
        self._values[key] = (value, stamp)
        return True

    def remove(self, key: str, timestamp: int, node: str) -> bool:
        if not isinstance(key, str) or not key:
            raise LWWMapError("key must be non-empty str")
        stamp = _check_stamp(timestamp, node)
        cur = self._tombstones.get(key)
        if cur is not None and cur >= stamp:
            return False
        self._tombstones[key] = stamp
        return True

    def get(self, key: str) -> Any:
        entry = self._values.get(key)
        if entry is None:
            raise LWWMapError(f"key {key!r} absent")
        tomb = self._tombstones.get(key)
        if tomb is not None and tomb >= entry[1]:
            raise LWWMapError(f"key {key!r} removed")
        return entry[0]

    def __contains__(self, key: object) -> bool:
        try:
            self.get(key)  # type: ignore[arg-type]
            return True
        except LWWMapError:
            return False

    def keys(self):
        return {k for k in self._values if k in self}

    def merge(self, other: "LWWMap") -> None:
        if not isinstance(other, LWWMap):
            raise LWWMapError("merge requires an LWWMap")
        for key, (value, stamp) in other._values.items():
            cur = self._values.get(key)
            if cur is None or stamp > cur[1]:
                self._values[key] = (value, stamp)
        for key, stamp in other._tombstones.items():
            cur = self._tombstones.get(key)
            if cur is None or stamp > cur:
                self._tombstones[key] = stamp


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for x in node.names:
                if x.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    a, b = LWWMap(), LWWMap()
    a.put("k", "A", 1, "n1")
    b.put("k", "B", 2, "n2")
    a.merge(b); b.merge(a)
    assert a.get("k") == b.get("k") == "B"
    # Remove then resurrect with a later put.
    a.remove("k", 3, "n1")
    assert "k" not in a
    b.put("k", "C", 4, "n2")
    a.merge(b)
    assert a.get("k") == "C"
    # Older remove does not resurrect-kill.
    c = LWWMap()
    c.put("k", "V", 10, "n1")
    c.remove("k", 5, "n2")
    assert c.get("k") == "V"
    # Fail-closed.
    try:
        a.put("", "v", 1, "n")
        raise AssertionError("should raise")
    except LWWMapError:
        pass
    assert stdlib_only()
    print("state_mgmt_28 OK: LWW-map put/remove/merge, resurrection")


if __name__ == "__main__":
    main()
