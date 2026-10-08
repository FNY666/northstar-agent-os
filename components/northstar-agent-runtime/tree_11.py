"""Sparse table: O(1) range-minimum queries after O(n log n) build. Stdlib only."""
from __future__ import annotations
from typing import List

class SparseTable:
    def __init__(self, data: List[int]) -> None:
        assert data
        n = len(data)
        self.n = n
        self.log = [0] * (n + 1)
        for i in range(2, n + 1): self.log[i] = self.log[i // 2] + 1
        k = self.log[n] + 1
        self.st = [[0] * n for _ in range(k)]
        self.st[0] = list(data)
        j = 1
        while (1 << j) <= n:
            for i in range(n - (1 << j) + 1):
                self.st[j][i] = min(self.st[j - 1][i], self.st[j - 1][i + (1 << (j - 1))])
            j += 1
    def query(self, l: int, r: int) -> int:
        assert 0 <= l <= r < self.n
        j = self.log[r - l + 1]
        return min(self.st[j][l], self.st[j][r - (1 << j) + 1])

def main() -> None:
    st = SparseTable([7, 2, 9, 1, 5, 3])
    assert st.query(0, 5) == 1
    assert st.query(0, 2) == 2
    assert st.query(3, 3) == 1
    assert st.query(4, 5) == 3
    print("tree_11 Sparse table OK")

if __name__ == "__main__":
    main()
