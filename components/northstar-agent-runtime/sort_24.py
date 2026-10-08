"""Radix sort (LSD): least-significant-digit, base 10.

Stable counting-style passes over decimal digits from least to most significant; negatives are sorted by magnitude and reversed.

What this IS: linear-time digit sort for fixed-width integers.

What this IS NOT:
* Base 10 is readable, not fastest (base 2^16 is typical).
* Needs the negative/magnitude split for signed input.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_24_VERSION = "sort-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-24.v1"


def _lsd(a: List[int]) -> List[int]:
    if not a:
        return a
    mx = max(a)
    exp = 1
    while mx // exp > 0:
        buckets: List[List[int]] = [[] for _ in range(10)]
        for x in a:
            buckets[(x // exp) % 10].append(x)
        a = [x for b in buckets for x in b]
        exp *= 10
    return a


def sort(data: List[int]) -> List[int]:
    # LSD radix sort, base 10: stable digit passes from least to most
    # significant. Negatives are sorted by magnitude and reversed.
    a = list(data)
    if not a:
        return a
    neg = [-x for x in a if x < 0]
    pos = [x for x in a if x >= 0]
    return [-x for x in _lsd(neg)[::-1]] + _lsd(pos)

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
    print("radix-lsd OK")


if __name__ == "__main__":
    main()
