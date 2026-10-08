"""running_median: running medians of a stream via two hand-rolled heaps (max-heap + min-heap). IS: a median per prefix; empty input or non-numbers raise ValueError. IS NOT: a sorted-list insertion (this is the two-heap streaming version)."""

from __future__ import annotations

import ast
from typing import List
VERSION = "queue-49.v1"

def _sift_up(h: List[float], i: int) -> None:
    while i > 0:
        p = (i - 1) // 2
        if h[i] < h[p]:
            h[i], h[p] = h[p], h[i]
            i = p
        else:
            break


def _sift_down(h: List[float], i: int) -> None:
    n = len(h)
    while True:
        l, r, s = 2 * i + 1, 2 * i + 2, i
        if l < n and h[l] < h[s]:
            s = l
        if r < n and h[r] < h[s]:
            s = r
        if s == i:
            break
        h[i], h[s] = h[s], h[i]
        i = s


def _hpush(h: List[float], x: float) -> None:
    h.append(x)
    _sift_up(h, len(h) - 1)


def _hpop(h: List[float]) -> float:
    top = h[0]
    last = h.pop()
    if h:
        h[0] = last
        _sift_down(h, 0)
    return top


def running_median(nums: List[float]) -> List[float]:
    """Return the median after each prefix of ``nums``."""
    if not isinstance(nums, list) or not nums:
        raise ValueError("nums must be a non-empty list")
    for x in nums:
        if isinstance(x, bool) or not isinstance(x, (int, float)):
            raise ValueError("nums must contain only real numbers")
    lo: List[float] = []  # max-heap (negated) of the lower half
    hi: List[float] = []  # min-heap of the upper half
    out: List[float] = []
    for x in nums:
        fx = float(x)
        if not lo or fx <= -lo[0]:
            _hpush(lo, -fx)
        else:
            _hpush(hi, fx)
        if len(lo) > len(hi) + 1:
            _hpush(hi, -_hpop(lo))
        elif len(hi) > len(lo):
            _hpush(lo, -_hpop(hi))
        if len(lo) > len(hi):
            out.append(float(-lo[0]))
        else:
            out.append((-lo[0] + hi[0]) / 2.0)
    return out


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
    assert running_median([5, 15, 1, 3]) == [5.0, 10.0, 5.0, 4.0]
    assert running_median([2]) == [2.0]
    assert running_median([1, 2, 3, 4, 5]) == [1.0, 1.5, 2.0, 2.5, 3.0]
    assert running_median([5, 4, 3, 2, 1]) == [5.0, 4.5, 4.0, 3.5, 3.0]
    try:
        running_median([])
    except ValueError:
        pass
    else:
        raise AssertionError("empty nums must raise ValueError")
    try:
        running_median([1, "2"])
    except ValueError:
        pass
    else:
        raise AssertionError("non-numeric item must raise ValueError")
    assert stdlib_only()
    print("queue-49 OK: two-heap running median")


if __name__ == "__main__":
    main()
