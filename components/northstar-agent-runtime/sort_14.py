"""Merge sort (natural): exploits existing ascending runs.

First scans for naturally occurring ascending runs, then merges runs pairwise; on sorted input it does a single linear scan.

What this IS: adaptive merge sort that is O(n) on already-sorted input.

What this IS NOT:
* Descending runs are not reversed here, only ascending runs merge.
* The merge phase is the same pairwise merge as top-down.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_14_VERSION = "sort-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-14.v1"


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
    # Natural merge sort: detect existing ascending runs first, then
    # merge runs pairwise until one run remains.
    a = list(data)
    n = len(a)
    if n <= 1:
        return a
    runs: List[List[int]] = []
    start = 0
    for i in range(1, n + 1):
        if i == n or a[i] < a[i - 1]:
            runs.append(a[start:i])
            start = i
    while len(runs) > 1:
        nxt: List[List[int]] = []
        for k in range(0, len(runs), 2):
            if k + 1 < len(runs):
                nxt.append(_merge(runs[k], runs[k + 1]))
            else:
                nxt.append(runs[k])
        runs = nxt
    return runs[0]

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
    print("merge-natural OK")


if __name__ == "__main__":
    main()
