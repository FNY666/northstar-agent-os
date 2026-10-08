"""Spreadsort (simplified): radix bucketing with insertion finish.

Recursively buckets integers by their top 8 bits (like a radix step), finishing small buckets with insertion sort; negatives handled by magnitude.

What this IS: the hybrid radix/insertion structure behind Boost's spreadsort.

What this IS NOT:
* Simplified: fixed 8-bit cascades instead of adaptive shift selection.
* Labeled simplified; not the full Boost implementation.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_48_VERSION = "sort-48.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-48.v1"


def _spread(a: List[int]) -> List[int]:
    if len(a) <= 32:
        for i in range(1, len(a)):
            key = a[i]
            j = i - 1
            while j >= 0 and a[j] > key:
                a[j + 1] = a[j]
                j -= 1
            a[j + 1] = key
        return a
    mx = max(a)
    shift = max(0, mx.bit_length() - 8)
    buckets: List[List[int]] = [[] for _ in range(256)]
    for x in a:
        buckets[(x >> shift) & 0xFF].append(x)
    out: List[int] = []
    for b in buckets:
        out.extend(_spread(b))
    return out


def sort(data: List[int]) -> List[int]:
    # Spreadsort (simplified): recursive radix bucketing on the top
    # 8 bits with insertion-sort finish for small buckets. Negatives
    # handled by magnitude.
    a = list(data)
    if not a:
        return a
    neg = [-x for x in a if x < 0]
    pos = [x for x in a if x >= 0]
    return [-x for x in _spread(neg)[::-1]] + _spread(pos)

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
    print("spreadsort OK")


if __name__ == "__main__":
    main()
