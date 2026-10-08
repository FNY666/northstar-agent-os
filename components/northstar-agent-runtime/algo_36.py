"""Fenwick tree (binary indexed tree) for prefix sums.

A Fenwick tree stores partial sums indexed by the lowbit trick, so
both point updates and prefix sums run in O(log n) with a tiny
constant and n words of memory.

Complexities: build O(n), add(i, delta) O(log n), prefix_sum O(log n),
range_sum O(log n). The public API is 0-indexed: prefix_sum(i) sums
data[0..i] inclusive, range_sum(l, r) sums data[l..r] inclusive.
"""

from __future__ import annotations

import ast
import sys
from typing import List, Sequence

ALGO_36_VERSION = "algo-36.v1"


class Fenwick:
    """Fenwick tree with a 0-indexed public API."""

    def __init__(self, data: Sequence[float] = ()) -> None:
        self.n = len(data)
        self._bit: List[float] = [0.0] * (self.n + 1)  # 1-indexed inside
        for i, v in enumerate(data):
            self.add(i, v)

    def __len__(self) -> int:
        return self.n

    def _check(self, i: int) -> None:
        if not 0 <= i < self.n:
            raise IndexError(f"index {i} out of range for length {self.n}")

    def add(self, i: int, delta: float) -> None:
        """Add delta to element i, O(log n)."""
        self._check(i)
        j = i + 1
        while j <= self.n:
            self._bit[j] += delta
            j += j & (-j)

    def prefix_sum(self, i: int) -> float:
        """Return sum(data[0..i]) inclusive, O(log n)."""
        self._check(i)
        s = 0.0
        j = i + 1
        while j > 0:
            s += self._bit[j]
            j -= j & (-j)
        return s

    def range_sum(self, l: int, r: int) -> float:
        """Return sum(data[l..r]) inclusive, O(log n)."""
        if not (0 <= l <= r < self.n):
            raise IndexError(f"invalid range [{l}, {r}] for length {self.n}")
        return self.prefix_sum(r) - (self.prefix_sum(l - 1) if l > 0 else 0.0)

    def get(self, i: int) -> float:
        """Return the current value of element i (helper)."""
        return self.range_sum(i, i)


def stdlib_only() -> bool:
    """Assert every imported top-level module is from the stdlib."""
    src = open(__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in stdlib, node.module
    return True


def main() -> None:
    f = Fenwick([1, 2, 3, 4, 5])
    assert f.prefix_sum(0) == 1
    assert f.prefix_sum(4) == 15
    assert f.range_sum(1, 3) == 9
    assert f.range_sum(2, 2) == 3
    f.add(2, 7)
    assert f.get(2) == 10
    assert f.prefix_sum(4) == 22
    assert f.range_sum(0, 4) == 22
    f.add(0, -1)
    assert f.prefix_sum(0) == 0
    single = Fenwick([9])
    assert single.prefix_sum(0) == 9
    assert single.range_sum(0, 0) == 9
    empty = Fenwick()
    assert len(empty) == 0
    try:
        empty.prefix_sum(0)
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError")
    assert stdlib_only()
    print("algo_36 OK")


if __name__ == "__main__":
    main()
