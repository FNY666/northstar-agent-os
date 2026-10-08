"""Euler tour tree (mock): subtree queries via tin/tout intervals. Stdlib only."""
from __future__ import annotations
from typing import Dict, List

class EulerTourMock:
    def __init__(self, n: int, children: Dict[int, List[int]], root: int = 0) -> None:
        self.n = n
        self.tin = [0] * n
        self.tout = [0] * n
        self.timer = 0
        self._dfs(root, children)
    def _dfs(self, u: int, children: Dict[int, List[int]]) -> None:
        self.tin[u] = self.timer; self.timer += 1
        for v in children.get(u, []):
            self._dfs(v, children)
        self.tout[u] = self.timer - 1
    def is_ancestor(self, u: int, v: int) -> bool:
        return self.tin[u] <= self.tin[v] <= self.tout[u]
    def subtree_nodes(self, u: int) -> List[int]:
        return [v for v in range(self.n)
                if self.tin[u] <= self.tin[v] <= self.tout[u]]
    def subtree_sum(self, u: int, vals: List[int]) -> int:
        return sum(vals[v] for v in self.subtree_nodes(u))

def main() -> None:
    children = {0: [1, 2], 1: [3], 2: []}
    et = EulerTourMock(4, children)
    assert et.is_ancestor(0, 3) and et.is_ancestor(1, 3)
    assert not et.is_ancestor(2, 3)
    assert sorted(et.subtree_nodes(1)) == [1, 3]
    assert et.subtree_sum(0, [1, 2, 3, 4]) == 10
    print("tree_16 Euler tour (mock) OK")

if __name__ == "__main__":
    main()
