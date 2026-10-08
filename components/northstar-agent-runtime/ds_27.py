"""DS: Segment Tree (27/50). segment tree for range sums"""
from __future__ import annotations

import ast

#: Module version.
DS_27_VERSION = "ds-27-segment-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-27.segment-tree.v1"


class SegmentTree:
    """Iterative segment tree for range sums with point updates."""

    def __init__(self, data):
        n = len(data)
        size = 1
        while size < n:
            size *= 2
        self._n = n
        self._size = size
        self._tree = [0] * (2 * size)
        for i, v in enumerate(data):
            self._tree[size + i] = v
        for i in range(size - 1, 0, -1):
            self._tree[i] = self._tree[2 * i] + self._tree[2 * i + 1]

    def update(self, index, value):
        if not 0 <= index < self._n:
            raise IndexError("index out of range")
        p = self._size + index
        self._tree[p] = value
        p //= 2
        while p:
            self._tree[p] = self._tree[2 * p] + self._tree[2 * p + 1]
            p //= 2

    def query(self, left, right):
        """Sum over [left, right)."""
        if not 0 <= left <= right <= self._n:
            raise ValueError("bad range")
        res = 0
        left += self._size
        right += self._size
        while left < right:
            if left & 1:
                res += self._tree[left]
                left += 1
            if right & 1:
                right -= 1
                res += self._tree[right]
            left //= 2
            right //= 2
        return res

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
    st = SegmentTree([1, 2, 3, 4, 5])
    assert st.query(0, 5) == 15
    assert st.query(1, 4) == 9
    st.update(2, 10)
    assert st.query(0, 5) == 22
    assert st.query(2, 3) == 10
    assert stdlib_only()
    print("ds-27 OK: range sum, point update")


if __name__ == "__main__":
    main()
