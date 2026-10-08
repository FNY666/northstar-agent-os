"""DS: Skip List (23/50). skip list

Mock: level randomization is stubbed; the ordered-map API is backed by a sorted list via bisect, so operations are correct but not expected-O(log n)."""
from __future__ import annotations

import ast
import bisect

#: Module version.
DS_23_VERSION = "ds-23-skip-list.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-23.skip-list.v1"


class SkipList:
    """API-compatible skip-list stub (see module docstring)."""

    def __init__(self):
        self._keys = []
        self._values = {}

    def insert(self, key, value=None):
        if key not in self._values:
            bisect.insort(self._keys, key)
        self._values[key] = value

    def search(self, key):
        return self._values.get(key)

    def delete(self, key):
        if key in self._values:
            del self._values[key]
            self._keys.remove(key)
            return True
        return False

    def keys(self):
        return list(self._keys)

    def __len__(self):
        return len(self._keys)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "bisect"}
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
    s = SkipList()
    s.insert(3, "c"); s.insert(1, "a"); s.insert(2, "b")
    assert s.keys() == [1, 2, 3]
    assert s.search(2) == "b"
    assert s.delete(2) is True
    assert s.keys() == [1, 3]
    assert stdlib_only()
    print("ds-23 OK: ordered-map API, sorted-list backend")


if __name__ == "__main__":
    main()
