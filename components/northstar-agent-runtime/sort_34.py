"""Strand sort: increasing-subsequence extraction.

Repeatedly pulls an increasing subsequence (a strand) out of the input and merges it into the output list.

What this IS: O(n^2) worst case, but O(n) on sorted input; natural for linked lists.

What this IS NOT:
* Popping from the front of a Python list is O(n) itself.
* Best on nearly-sorted data.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_34_VERSION = "sort-34.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-34.v1"


def _merge(left: List[int], right: List[int]) -> List[int]:
    out: List[int] = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            out.append(left[i])
            i += 1
        else:
            out.append(right[j])
            j += 1
    out.extend(left[i:])
    out.extend(right[j:])
    return out


def sort(data: List[int]) -> List[int]:
    # Strand sort: repeatedly pull an increasing subsequence (strand)
    # out of the input and merge it into the output.
    a = list(data)
    out: List[int] = []
    while a:
        strand = [a.pop(0)]
        i = 0
        while i < len(a):
            if a[i] >= strand[-1]:
                strand.append(a.pop(i))
            else:
                i += 1
        out = _merge(out, strand)
    return out

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
    print("strand OK")


if __name__ == "__main__":
    main()
