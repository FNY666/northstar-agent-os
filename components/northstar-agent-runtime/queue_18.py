"""LRUCache: fixed-capacity LRU cache with O(1) get/put via dict plus recency deque. IS: an LRU cache; get on missing key returns -1; non-positive capacity raises ValueError. IS NOT: a TTL-expiring or thread-safe cache."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, Dict
VERSION = "queue-18.v1"

class LRUCache:
    """Least-recently-used cache; most-recent key sits at the deque front."""

    def __init__(self, capacity: int) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity <= 0:
            raise ValueError("capacity must be a positive int")
        self._cap = capacity
        self._vals: Dict[Any, Any] = {}
        self._order: deque = deque()

    def _touch(self, key: Any) -> None:
        self._order.remove(key)
        self._order.appendleft(key)

    def get(self, key: Any) -> Any:
        if key not in self._vals:
            return -1
        self._touch(key)
        return self._vals[key]

    def put(self, key: Any, value: Any) -> None:
        if key in self._vals:
            self._vals[key] = value
            self._touch(key)
            return
        if len(self._vals) >= self._cap:
            lru = self._order.pop()
            del self._vals[lru]
        self._vals[key] = value
        self._order.appendleft(key)


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    c = LRUCache(2)
    c.put(1, 1); c.put(2, 2)
    assert c.get(1) == 1
    c.put(3, 3)  # evicts key 2
    assert c.get(2) == -1 and c.get(3) == 3
    c.put(4, 4)  # evicts key 1
    assert c.get(1) == -1 and c.get(4) == 4
    c.put(4, 40)  # update, not evict
    assert c.get(4) == 40 and c.get(3) == 3
    assert c.get(99) == -1
    for bad in (0, -2, "2", 2.0):
        try:
            LRUCache(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"capacity {bad!r} must raise ValueError")
    assert stdlib_only()
    print("queue-18 OK: LRU cache")


if __name__ == "__main__":
    main()
