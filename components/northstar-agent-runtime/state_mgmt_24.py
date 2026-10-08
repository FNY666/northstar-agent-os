"""State 24: last-write-wins register.

LWW register: set(value, timestamp, node) keeps the write with the
highest (timestamp, node) pair.  Reads always return the current
winner.  merge(other) takes the element-wise winner.

Timestamp ties break on node id, so replicas converge deterministically
without coordination.

Fail-closed: negative timestamps, empty node, or merging registers
with different names raise.
"""

from __future__ import annotations

import ast
from typing import Any, Optional, Tuple


MODULE_VERSION = "state-mgmt-24.v1"
SCHEMA_PIN = "northstar.state-mgmt-24.v1"


class LWWError(Exception):
    pass


class LWWRegister:
    def __init__(self, name: str) -> None:
        if not name:
            raise LWWError("name required")
        self.name = name
        self._entry: Optional[Tuple[Any, int, str]] = None  # (value, ts, node)

    def set(self, value: Any, timestamp: int, node: str) -> bool:
        """Set if (timestamp, node) beats the current.  Returns True if
        the write was accepted."""
        if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
            raise LWWError("timestamp must be non-negative int")
        if not node:
            raise LWWError("node required")
        cur = self._entry
        if cur is None or (timestamp, node) > (cur[1], cur[2]):
            self._entry = (value, timestamp, node)
            return True
        return False

    def get(self) -> Any:
        if self._entry is None:
            raise LWWError("register is empty")
        return self._entry[0]

    def stamp(self) -> Tuple[int, str]:
        if self._entry is None:
            raise LWWError("register is empty")
        return (self._entry[1], self._entry[2])

    def merge(self, other: "LWWRegister") -> None:
        if not isinstance(other, LWWRegister):
            raise LWWError("merge requires an LWWRegister")
        if other.name != self.name:
            raise LWWError(f"name mismatch: {self.name!r} vs {other.name!r}")
        if other._entry is None:
            return
        cur = self._entry
        if cur is None or (other._entry[1], other._entry[2]) > (cur[1], cur[2]):
            self._entry = other._entry


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
    r = LWWRegister("cfg")
    assert r.set("v1", 10, "n1") is True
    assert r.set("v0", 5, "n2") is False   # older write rejected
    assert r.get() == "v1"
    assert r.set("v2", 10, "n2") is True   # tie -> higher node wins
    assert r.get() == "v2"
    # Merge converges.
    a, b = LWWRegister("x"), LWWRegister("x")
    a.set("A", 1, "n1")
    b.set("B", 2, "n2")
    a.merge(b); b.merge(a)
    assert a.get() == b.get() == "B"
    # Empty read -> fail-closed; name mismatch -> fail-closed.
    try:
        LWWRegister("e").get()
        raise AssertionError("should raise")
    except LWWError:
        pass
    try:
        a.merge(LWWRegister("other"))
        raise AssertionError("should raise")
    except LWWError:
        pass
    assert stdlib_only()
    print("state_mgmt_24 OK: LWW set/get/merge, tie-break, fail-closed")


if __name__ == "__main__":
    main()
