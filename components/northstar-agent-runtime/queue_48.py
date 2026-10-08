"""top_k_frequent: k most frequent items via a bounded min-heap of size k. IS: k items by descending frequency; k < 1 or k > distinct raises ValueError. IS NOT: a full sort by frequency (this keeps only k heap entries)."""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Tuple
VERSION = "queue-48.v1"

def _sift_up(h: List[Tuple[int, int, Any]], i: int) -> None:
    while i > 0:
        p = (i - 1) // 2
        if h[i][:2] < h[p][:2]:
            h[i], h[p] = h[p], h[i]
            i = p
        else:
            break


def _sift_down(h: List[Tuple[int, int, Any]], i: int) -> None:
    n = len(h)
    while True:
        l, r, s = 2 * i + 1, 2 * i + 2, i
        if l < n and h[l][:2] < h[s][:2]:
            s = l
        if r < n and h[r][:2] < h[s][:2]:
            s = r
        if s == i:
            break
        h[i], h[s] = h[s], h[i]
        i = s


def top_k_frequent(nums: List[Any], k: int) -> List[Any]:
    """Return the ``k`` most frequent items, most frequent first."""
    if not isinstance(nums, list) or not nums:
        raise ValueError("nums must be a non-empty list")
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        raise ValueError("k must be a positive int")
    freq: Dict[Any, int] = {}
    for x in nums:
        try:
            freq[x] = freq.get(x, 0) + 1
        except TypeError:
            raise ValueError("items must be hashable")
    if k > len(freq):
        raise ValueError("k must not exceed the number of distinct items")
    heap: List[Tuple[int, int, Any]] = []
    seq = 0
    for val, cnt in freq.items():
        entry = (cnt, seq, val)
        seq += 1
        if len(heap) < k:
            heap.append(entry)
            _sift_up(heap, len(heap) - 1)
        elif (cnt, seq) > heap[0][:2]:
            heap[0] = entry
            _sift_down(heap, 0)
    return [val for _, _, val in sorted(heap, key=lambda e: (-e[0], e[1]))]


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert top_k_frequent([1, 1, 1, 2, 2, 3], 2) == [1, 2]
    assert top_k_frequent([1], 1) == [1]
    assert top_k_frequent(["a", "b", "a", "c", "b", "a"], 1) == ["a"]
    r = top_k_frequent([4, 4, 4, 2, 2, 1], 3)
    assert r[0] == 4 and sorted(r) == [1, 2, 4]
    try:
        top_k_frequent([1, 2], 3)
    except ValueError:
        pass
    else:
        raise AssertionError("k > distinct must raise ValueError")
    try:
        top_k_frequent([], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("empty nums must raise ValueError")
    assert stdlib_only()
    print("queue-48 OK: bounded-heap top-k")


if __name__ == "__main__":
    main()
