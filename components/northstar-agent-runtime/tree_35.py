"""Suffix array: sorted suffix indices + LCP (tree-adjacent). Stdlib only."""
from __future__ import annotations
from typing import List

def build_sa(text: str) -> List[int]:
    return sorted(range(len(text)), key=lambda i: text[i:])

def build_lcp(text: str, sa: List[int]) -> List[int]:
    n = len(text)
    rank = [0] * n
    for i, s in enumerate(sa): rank[s] = i
    lcp = [0] * n
    h = 0
    for i in range(n):
        r = rank[i]
        if r > 0:
            j = sa[r - 1]
            while i + h < n and j + h < n and text[i + h] == text[j + h]:
                h += 1
            lcp[r] = h
            if h > 0: h -= 1
    return lcp

def main() -> None:
    sa = build_sa("banana")
    assert sa == [5, 3, 1, 0, 4, 2]
    lcp = build_lcp("banana", sa)
    assert lcp == [0, 1, 3, 0, 0, 2]
    assert build_sa("a") == [0]
    print("tree_35 Suffix array OK")

if __name__ == "__main__":
    main()
