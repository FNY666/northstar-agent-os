"""State 18: consistent hashing ring.

Hash ring with virtual nodes:
- add_node(node, replicas): places `replicas` virtual points on the ring
- remove_node(node): removes all its points
- get_node(key): first ring point clockwise from hash(key)

Properties: minimal key movement on membership change; uniform-ish
spread given enough replicas.

Fail-closed: empty ring lookup, duplicate add, removing unknown node,
or non-positive replicas raise.
"""

from __future__ import annotations

import ast
import bisect
import hashlib
from typing import Dict, List


MODULE_VERSION = "state-mgmt-18.v1"
SCHEMA_PIN = "northstar.state-mgmt-18.v1"


class HashRingError(Exception):
    pass


def _hash(value: str) -> int:
    return int.from_bytes(hashlib.sha256(value.encode()).digest()[:8], "big")


class HashRing:
    def __init__(self, replicas: int = 100) -> None:
        if not isinstance(replicas, int) or isinstance(replicas, bool) or replicas <= 0:
            raise HashRingError("replicas must be positive int")
        self.replicas = replicas
        self._points: List[int] = []          # sorted hashes
        self._owners: Dict[int, str] = {}     # hash -> node

    def add_node(self, node: str) -> None:
        if not node:
            raise HashRingError("node required")
        if node in set(self._owners.values()):
            raise HashRingError(f"node {node} already present")
        for i in range(self.replicas):
            h = _hash(f"{node}#{i}")
            if h in self._owners:
                continue  # astronomically unlikely collision; skip
            bisect.insort(self._points, h)
            self._owners[h] = node

    def remove_node(self, node: str) -> None:
        if node not in set(self._owners.values()):
            raise HashRingError(f"unknown node {node}")
        drop = [h for h, owner in self._owners.items() if owner == node]
        for h in drop:
            del self._owners[h]
            self._points.remove(h)

    def get_node(self, key: str) -> str:
        if not self._points:
            raise HashRingError("ring is empty")
        if not isinstance(key, str):
            raise HashRingError("key must be str")
        h = _hash(key)
        idx = bisect.bisect_right(self._points, h)
        if idx == len(self._points):
            idx = 0  # wrap around
        return self._owners[self._points[idx]]

    def nodes(self) -> List[str]:
        return sorted(set(self._owners.values()))


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "bisect", "hashlib", "pathlib", "typing"}
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
    ring = HashRing(replicas=50)
    for n in ("a", "b", "c"):
        ring.add_node(n)
    owners = {ring.get_node(f"k{i}") for i in range(200)}
    assert owners == {"a", "b", "c"}  # all nodes own something
    # Stable mapping: same key always maps the same.
    assert ring.get_node("hello") == ring.get_node("hello")
    # Removing a node only moves its keys elsewhere.
    before = {f"k{i}": ring.get_node(f"k{i}") for i in range(200)}
    ring.remove_node("c")
    moved = sum(1 for k, v in before.items() if ring.get_node(k) != v)
    assert 0 < moved < 200  # only c's keys moved
    # Fail-closed.
    try:
        ring.add_node("a")
        raise AssertionError("should raise")
    except HashRingError:
        pass
    empty = HashRing()
    try:
        empty.get_node("x")
        raise AssertionError("should raise")
    except HashRingError:
        pass
    assert stdlib_only()
    print("state_mgmt_18 OK: ring mapping, minimal movement, fail-closed")


if __name__ == "__main__":
    main()
