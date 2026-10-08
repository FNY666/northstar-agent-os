"""Segment tree: range sum with point updates. Stdlib only."""
from __future__ import annotations
from typing import List

class SegmentTree:
    def __init__(self, data: List[int]) -> None:
        n = len(data)
        assert n > 0
        self.n = n
        self.tree = [0] * (4 * n)
        self._build(data, 1, 0, n - 1)
    def _build(self, data, v, l, r):
        if l == r:
            self.tree[v] = data[l]
        else:
            m = (l + r) // 2
            self._build(data, 2 * v, l, m)
            self._build(data, 2 * v + 1, m + 1, r)
            self.tree[v] = self.tree[2 * v] + self.tree[2 * v + 1]
    def update(self, idx: int, val: int) -> None:
        self._update(1, 0, self.n - 1, idx, val)
    def _update(self, v, l, r, idx, val):
        if l == r:
            self.tree[v] = val
        else:
            m = (l + r) // 2
            if idx <= m: self._update(2 * v, l, m, idx, val)
            else: self._update(2 * v + 1, m + 1, r, idx, val)
            self.tree[v] = self.tree[2 * v] + self.tree[2 * v + 1]
    def query(self, l: int, r: int) -> int:
        return self._query(1, 0, self.n - 1, l, r)
    def _query(self, v, tl, tr, l, r):
        if l > r: return 0
        if l == tl and r == tr: return self.tree[v]
        m = (tl + tr) // 2
        return self._query(2 * v, tl, m, l, min(r, m)) +                self._query(2 * v + 1, m + 1, tr, max(l, m + 1), r)

def main() -> None:
    st = SegmentTree([1, 2, 3, 4, 5])
    assert st.query(0, 4) == 15
    assert st.query(1, 3) == 9
    st.update(2, 10)
    assert st.query(0, 4) == 22
    assert st.query(2, 2) == 10
    print("tree_09 Segment tree OK")

if __name__ == "__main__":
    main()
