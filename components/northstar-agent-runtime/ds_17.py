"""DS: Hash Table (17/50). hash table with separate chaining"""
from __future__ import annotations

import ast

#: Module version.
DS_17_VERSION = "ds-17-hash-table.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-17.hash-table.v1"


class HashTable:
    """Hash table with separate chaining."""

    def __init__(self, capacity=16):
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._buckets = [[] for _ in range(capacity)]
        self._size = 0

    def _index(self, key):
        return hash(key) % len(self._buckets)

    def put(self, key, value):
        bucket = self._buckets[self._index(key)]
        for i, (k, _v) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, value)
                return
        bucket.append((key, value))
        self._size += 1

    def get(self, key):
        bucket = self._buckets[self._index(key)]
        for k, v in bucket:
            if k == key:
                return v
        raise KeyError(key)

    def delete(self, key):
        bucket = self._buckets[self._index(key)]
        for i, (k, _v) in enumerate(bucket):
            if k == key:
                del bucket[i]
                self._size -= 1
                return True
        return False

    def __len__(self):
        return self._size

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    h = HashTable(capacity=4)
    h.put("a", 1); h.put("b", 2); h.put("a", 10)
    assert h.get("a") == 10
    assert h.get("b") == 2
    assert len(h) == 2
    assert h.delete("b") is True
    assert h.delete("b") is False
    assert stdlib_only()
    print("ds-17 OK: separate chaining put/get/delete")


if __name__ == "__main__":
    main()
