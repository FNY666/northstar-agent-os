"""Radix sort (MSD): most-significant-digit recursive bucketing.

Buckets by the most significant decimal digit first, then recurses into each bucket on the next digit; small buckets finish directly.

What this IS: top-down radix sort; can skip empty bucket ranges early.

What this IS NOT:
* Recursion overhead per digit level.
* Same negative/magnitude split as LSD.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_25_VERSION = "sort-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-25.v1"


def _msd_rec(a: List[int], exp: int) -> List[int]:
    if len(a) <= 1 or exp == 0:
        return list(a)
    buckets: List[List[int]] = [[] for _ in range(10)]
    for x in a:
        buckets[(x // exp) % 10].append(x)
    out: List[int] = []
    for b in buckets:
        out.extend(_msd_rec(b, exp // 10))
    return out


def _msd(a: List[int]) -> List[int]:
    if not a:
        return a
    mx = max(a)
    exp = 1
    while mx // (exp * 10) > 0:
        exp *= 10
    return _msd_rec(a, exp)


def sort(data: List[int]) -> List[int]:
    # MSD radix sort, base 10: recursively bucket by most significant
    # digit first. Negatives handled by magnitude.
    a = list(data)
    if not a:
        return a
    neg = [-x for x in a if x < 0]
    pos = [x for x in a if x >= 0]
    return [-x for x in _msd(neg)[::-1]] + _msd(pos)

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
    assert sort([]) == []
    assert sort([1]) == [1]
    assert sort([3, 1, 2]) == [1, 2, 3]
    assert sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert sort([-3, 0, -1, 2]) == [-3, -1, 0, 2]
    assert sort([2, 2, 1, 1]) == [1, 1, 2, 2]
    assert stdlib_only()
    print("radix-msd OK")


if __name__ == "__main__":
    main()
