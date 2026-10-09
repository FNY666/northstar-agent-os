"""Y-module: bsearch_index -- Binary search index or -1."""
from __future__ import annotations
VERSION = "y_47.v1"
def bsearch_index(xs: list, x) -> int:
    lo, hi = 0, len(xs) - 1
    while lo <= hi:
        m = (lo + hi) // 2
        if xs[m] == x: return m
        lo, hi = (m+1, hi) if xs[m] < x else (lo, m-1)
    return -1

def main() -> None:
    assert bsearch_index([1, 3, 5, 7], 5) == 2
    assert bsearch_index([1, 3], 4) == -1
    print("y_47 bsearch_index OK")
if __name__ == "__main__": main()
