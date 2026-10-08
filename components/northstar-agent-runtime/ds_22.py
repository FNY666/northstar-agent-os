"""DS: Bloom Filter (22/50). bloom filter

Mock: exact-set backend: might_contain has no false negatives and (unlike a real bloom filter) no false positives either; the probabilistic bit-array is not implemented."""
from __future__ import annotations

import ast

#: Module version.
DS_22_VERSION = "ds-22-bloom-filter.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-22.bloom-filter.v1"


class BloomFilter:
    """API-compatible bloom-filter stub (see module docstring)."""

    def __init__(self, capacity=1000, fp_rate=0.01):
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self.fp_rate = fp_rate
        self._items = set()

    def add(self, item):
        self._items.add(item)

    def might_contain(self, item):
        return item in self._items

    def __len__(self):
        return len(self._items)

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
    bf = BloomFilter(capacity=100)
    bf.add("hello"); bf.add("world")
    assert bf.might_contain("hello") is True
    assert bf.might_contain("other") is False
    assert len(bf) == 2
    assert stdlib_only()
    print("ds-22 OK: add/might_contain, exact backend")


if __name__ == "__main__":
    main()
