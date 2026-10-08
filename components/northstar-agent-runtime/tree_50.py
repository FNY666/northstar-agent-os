"""LCA with binary lifting: O(log n) ancestor queries. Stdlib only."""
from __future__ import annotations
from typing import Dict, List

class LCATree:
    def __init__(self, n: int, children: Dict[int, List[int]], root: int = 0) -> None:
        self.n = n
        self.LOG = max(1, (n).bit_length())
        self.up = [[-1] * n for _ in range(self.LOG)]
        self.depth = [0] * n
        self._dfs(root, -1, 0, children)
        for k in range(1, self.LOG):
            for v in range(n):
                p = self.up[k - 1][v]
                self.up[k][v] = self.up[k - 1][p] if p != -1 else -1
    def _dfs(self, u, parent, d, children) -> None:
        self.up[0][u] = parent
        self.depth[u] = d
        for v in children.get(u, []):
            self._dfs(v, u, d + 1, children)
    def lca(self, a: int, b: int) -> int:
        if self.depth[a] < self.depth[b]: a, b = b, a
        diff = self.depth[a] - self.depth[b]
        for k in range(self.LOG):
            if diff >> k & 1: a = self.up[k][a]
        if a == b: return a
        for k in range(self.LOG - 1, -1, -1):
            if self.up[k][a] != self.up[k][b]:
                a, b = self.up[k][a], self.up[k][b]
        return self.up[0][a]
    def kth_ancestor(self, v: int, k: int) -> int:
        for i in range(self.LOG):
            if k >> i & 1:
                v = self.up[i][v]
                if v == -1: break
        return v

def main() -> None:
    children = {0: [1, 2], 1: [3, 4], 2: [5]}
    t = LCATree(6, children)
    assert t.lca(3, 4) == 1
    assert t.lca(3, 5) == 0
    assert t.lca(1, 3) == 1
    assert t.kth_ancestor(3, 2) == 0
    assert t.kth_ancestor(5, 1) == 2
    print("tree_50 LCA binary lifting OK")

if __name__ == "__main__":
    main()
