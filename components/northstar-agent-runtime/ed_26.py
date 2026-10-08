"""Hirschberg linear-space alignment

Edit distance plus alignment using only O(n) space.

What this IS: Hirschberg's divide-and-conquer: (distance, aligned_a, aligned_b).

What this IS NOT:
* the full-matrix backtrace -- ed_28 keeps the whole matrix.
* distance only -- the alignment strings are returned too.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_26_VERSION = "ed-26.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-26.v1"


def _lev_row(a: str, b: str) -> List[int]:
    prev = list(range(len(b) + 1))
    for ch in a:
        cur = [0] * (len(b) + 1)
        cur[0] = prev[0] + 1
        for j, bch in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (ch != bch))
        prev = cur
    return prev


def _nw_backtrace(a: str, b: str) -> Tuple[int, str, str]:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
                           dp[i - 1][j - 1] + cost)
    i, j = m, n
    ra, rb = [], []
    while i > 0 or j > 0:
        if i > 0 and j > 0:
            cost = 0 if a[i - 1] == b[j - 1] else 1
            if dp[i][j] == dp[i - 1][j - 1] + cost:
                ra.append(a[i - 1])
                rb.append(b[j - 1])
                i -= 1
                j -= 1
                continue
        if i > 0 and dp[i][j] == dp[i - 1][j] + 1:
            ra.append(a[i - 1])
            rb.append("-")
            i -= 1
            continue
        ra.append("-")
        rb.append(b[j - 1])
        j -= 1
    return (dp[m][n], "".join(reversed(ra)), "".join(reversed(rb)))


def hirschberg(a: str, b: str) -> Tuple[int, str, str]:
    """Hirschberg alignment: (distance, aligned_a, aligned_b)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if len(a) == 0:
        return (len(b), "-" * len(b), b)
    if len(b) == 0:
        return (len(a), a, "-" * len(a))
    if len(a) == 1 or len(b) == 1:
        return _nw_backtrace(a, b)
    mid = len(a) // 2
    left = _lev_row(a[:mid], b)
    right = _lev_row(a[mid:][::-1], b[::-1])
    n = len(b)
    best = min(range(n + 1), key=lambda j: left[j] + right[n - j])
    dl, la, lb = hirschberg(a[:mid], b[:best])
    dr, ra, rb = hirschberg(a[mid:], b[best:])
    return (dl + dr, la + ra, lb + rb)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    d, aa, bb = hirschberg("kitten", "sitting")
    assert d == 3
    assert len(aa) == len(bb)
    assert aa.replace("-", "") == "kitten"
    assert bb.replace("-", "") == "sitting"
    assert hirschberg("", "abc")[0] == 3
    assert hirschberg("abc", "abc")[0] == 0
    try:
        hirschberg("a", 5)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("26-hirschberg OK")


if __name__ == "__main__":
    main()
