"""DS: Multiset (19/50). multiset (Counter-based)"""
from __future__ import annotations

import ast
import collections

#: Module version.
DS_19_VERSION = "ds-19-multiset.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-19.multiset.v1"


class Multiset:
    """Multiset backed by collections.Counter."""

    def __init__(self, items=()):
        self._counts = collections.Counter(items)

    def add(self, value, n=1):
        if n < 0:
            raise ValueError("n must be non-negative")
        self._counts[value] += n

    def remove(self, value, n=1):
        if self._counts[value] < n:
            raise ValueError("not enough copies")
        self._counts[value] -= n
        if self._counts[value] == 0:
            del self._counts[value]

    def count(self, value):
        return self._counts.get(value, 0)

    def total(self):
        return sum(self._counts.values())

    def __len__(self):
        return len(self._counts)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "collections"}
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
    ms = Multiset(["a", "b", "a"])
    assert ms.count("a") == 2
    ms.add("a")
    assert ms.count("a") == 3
    ms.remove("a", 2)
    assert ms.count("a") == 1
    assert ms.total() == 2
    assert stdlib_only()
    print("ds-19 OK: count/add/remove with multiplicities")


if __name__ == "__main__":
    main()
