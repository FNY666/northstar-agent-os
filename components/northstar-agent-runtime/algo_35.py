"""Segment tree for range-sum queries with point updates.

A segment tree stores the array in its leaves and each internal node
holds the sum of its segment, so a range sum only needs O(log n) node
visits instead of scanning the range.

Complexities: build O(n), query(l, r) O(log n), point update O(log n).
Ranges are inclusive 0-based indices.

Implemented iteratively over a power-of-two sized array for simplicity.
"""

from __future__ import annotations

import ast
import sys
from typing import List, Sequence

ALGO_35_VERSION = "algo-35.v1"


class SegmentTree:
    """Iterative segment tree for range-sum queries."""

    def __init__(self, data: Sequence[float]) -> None:
        self.n = len(data)
        size = 1
        while size < max(self.n, 1):
            size *= 2
        self._size = size
        self._tree: List[float] = [0.0] * (2 * size)
        for i, v in enumerate(data):
            self._tree[size + i] = v
        for i in range(size - 1, 0, -1):
            self._tree[i] = self._tree[2 * i] + self._tree[2 * i + 1]

    def __len__(self) -> int:
        return self.n

    def _check_index(self, i: int) -> None:
        if not 0 <= i < self.n:
            raise IndexError(f"index {i} out of range for length {self.n}")

    def update(self, i: int, val: float) -> None:
        """Set element i to val (point update), O(log n)."""
        self._check_index(i)
        p = self._size + i
        self._tree[p] = val
        p //= 2
        while p:
            self._tree[p] = self._tree[2 * p] + self._tree[2 * p + 1]
            p //= 2

    def query(self, l: int, r: int) -> float:
        """Return sum(data[l..r]) inclusive, O(log n)."""
        if self.n == 0:
            raise IndexError("query on empty segment tree")
        if not (0 <= l <= r < self.n):
            raise IndexError(f"invalid range [{l}, {r}] for length {self.n}")
        l += self._size
        r += self._size
        res = 0.0
        while l <= r:
            if l % 2 == 1:
                res += self._tree[l]
                l += 1
            if r % 2 == 0:
                res += self._tree[r]
                r -= 1
            l //= 2
            r //= 2
        return res


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
    st = SegmentTree([1, 3, 5, 7, 9, 11])
    assert st.query(0, 5) == 36
    assert st.query(1, 3) == 15
    assert st.query(2, 2) == 5
    assert st.query(0, 0) == 1
    st.update(1, 10)
    assert st.query(0, 5) == 43
    assert st.query(1, 1) == 10
    st.update(5, 0)
    assert st.query(4, 5) == 9
    single = SegmentTree([42])
    assert single.query(0, 0) == 42
    single.update(0, 7)
    assert single.query(0, 0) == 7
    assert len(single) == 1
    empty = SegmentTree([])
    assert len(empty) == 0
    try:
        empty.query(0, 0)
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError")
    assert stdlib_only()
    print("algo_35 OK")


if __name__ == "__main__":
    main()
