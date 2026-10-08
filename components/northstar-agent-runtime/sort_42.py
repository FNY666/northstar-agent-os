"""Permutation sort (mock): next-permutation until sorted; capped.

Enumerates permutations of the input until one is sorted; refuses inputs longer than max_n.

What this IS: an educational mock of the factorial-time joke sort.

What this IS NOT:
* O(n!) permutations -- the cap is the only safety.
* itertools.permutations does the enumeration work.
"""

from __future__ import annotations

import ast
import itertools
from typing import List

#: Module version.
SORT_42_VERSION = "sort-42.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-42.v1"


def sort(data: List[int], max_n: int = 8) -> List[int]:
    # Permutation sort (educational mock): enumerate permutations
    # until one is sorted. Refuses inputs larger than max_n.
    a = list(data)
    if len(a) > max_n:
        raise ValueError("permutation sort refuses inputs larger than %d" % max_n)
    for p in itertools.permutations(a):
        if all(p[i] <= p[i + 1] for i in range(len(p) - 1)):
            return list(p)
    return a

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "itertools", "pathlib", "typing"}
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
    print("permutation OK")


if __name__ == "__main__":
    main()
