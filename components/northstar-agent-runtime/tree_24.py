"""BK-tree: metric-space search (e.g. edit distance). Stdlib only."""
from __future__ import annotations
from typing import Callable, Dict, List, Tuple

def edit_distance(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            prev, dp[j] = dp[j], min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] != b[j - 1]))
    return dp[n]

class BKTree:
    def __init__(self, dist: Callable = edit_distance) -> None:
        self.dist = dist
        self.root = None  # (word, {d: child})
    def insert(self, word: str) -> None:
        if self.root is None:
            self.root = (word, {}); return
        node = self.root
        while True:
            w, children = node
            d = self.dist(word, w)
            if d == 0: return
            if d in children: node = children[d]
            else:
                children[d] = (word, {}); return
    def query(self, word: str, tol: int) -> List[Tuple[str, int]]:
        out: List[Tuple[str, int]] = []
        def rec(node):
            w, children = node
            d = self.dist(word, w)
            if d <= tol: out.append((w, d))
            for dd, child in children.items():
                if abs(dd - d) <= tol: rec(child)
        if self.root is not None: rec(self.root)
        return sorted(out, key=lambda x: (x[1], x[0]))

def main() -> None:
    bk = BKTree()
    for w in ["book", "books", "cake", "boo", "cape"]: bk.insert(w)
    got = bk.query("book", 1)
    assert [w for w, _ in got] == ["book", "boo", "books"]
    assert bk.query("xyz", 1) == []
    assert bk.query("cake", 0) == [("cake", 0)]
    print("tree_24 BK-tree OK")

if __name__ == "__main__":
    main()
