"""Fenwick tree (Binary Indexed Tree): prefix sums, point updates. Stdlib only."""
from __future__ import annotations
from typing import List

class Fenwick:
    def __init__(self, n: int) -> None:
        assert n > 0
        self.n = n
        self.bit = [0] * (n + 1)
    @classmethod
    def from_list(cls, data: List[int]) -> "Fenwick":
        f = cls(len(data))
        for i, v in enumerate(data): f.add(i, v)
        return f
    def add(self, idx: int, delta: int) -> None:
        i = idx + 1
        while i <= self.n:
            self.bit[i] += delta
            i += i & -i
    def prefix(self, idx: int) -> int:
        s, i = 0, idx + 1
        while i > 0:
            s += self.bit[i]
            i -= i & -i
        return s
    def range_sum(self, l: int, r: int) -> int:
        return self.prefix(r) - (self.prefix(l - 1) if l > 0 else 0)

def main() -> None:
    f = Fenwick.from_list([1, 2, 3, 4, 5])
    assert f.prefix(4) == 15
    assert f.range_sum(1, 3) == 9
    f.add(0, 10)
    assert f.prefix(0) == 11
    assert f.range_sum(0, 4) == 25
    print("tree_10 Fenwick OK")

if __name__ == "__main__":
    main()
