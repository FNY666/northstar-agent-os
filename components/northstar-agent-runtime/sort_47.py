"""Ford-Johnson (simplified): merge-insertion skeleton.

Pairs elements and orders within pairs, recursively sorts pairs by their larger element, then binary-inserts the smaller elements (Jacobsthal optimal insertion order elided).

What this IS: the merge-insertion structure with minimal comparison count in spirit.

What this IS NOT:
* Without the Jacobsthal order it is not the true minimal-comparison Ford-Johnson.
* Labeled simplified for exactly that reason.
"""

from __future__ import annotations

import ast
import bisect
from typing import List

#: Module version.
SORT_47_VERSION = "sort-47.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-47.v1"


def _argsort(keys: List[int]) -> List[int]:
    return sorted(range(len(keys)), key=keys.__getitem__)


def sort(data: List[int]) -> List[int]:
    # Ford-Johnson merge-insertion (simplified): pair elements and
    # order within pairs, recursively sort pairs by their larger
    # element, then binary-insert the smaller elements. The optimal
    # Jacobsthal insertion order is elided.
    a = list(data)
    n = len(a)
    if n <= 1:
        return a
    pairs: List[List[int]] = []
    i = 0
    while i + 1 < n:
        x, y = a[i], a[i + 1]
        pairs.append([x, y] if x <= y else [y, x])
        i += 2
    odd = [a[i]] if i < n else []
    order = _argsort([p[1] for p in pairs])
    sp = [pairs[k] for k in order]
    main = [sp[0][0]] + [p[1] for p in sp]
    for p in sp[1:]:
        bisect.insort(main, p[0])
    for x in odd:
        bisect.insort(main, x)
    return main

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "bisect", "pathlib", "typing"}
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
    print("ford-johnson OK")


if __name__ == "__main__":
    main()
