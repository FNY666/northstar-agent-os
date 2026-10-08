"""Cycle sort: minimal-write rotation placement.

For each position, counts how many smaller elements exist to find its final spot, then rotates the displaced cycle into place; optimal write count.

What this IS: the comparison sort with the minimal number of writes: O(n) writes.

What this IS NOT:
* Still O(n^2) comparisons.
* Valuable for EEPROM/flash where writes are expensive.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_32_VERSION = "sort-32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-32.v1"


def sort(data: List[int]) -> List[int]:
    # Cycle sort: for each position, count smaller elements to find
    # its final spot, then rotate the cycle. Minimal writes.
    a = list(data)
    n = len(a)
    for start in range(n - 1):
        item = a[start]
        pos = start
        for j in range(start + 1, n):
            if a[j] < item:
                pos += 1
        if pos == start:
            continue
        while item == a[pos]:
            pos += 1
        a[pos], item = item, a[pos]
        while pos != start:
            pos = start
            for j in range(start + 1, n):
                if a[j] < item:
                    pos += 1
            while item == a[pos]:
                pos += 1
            a[pos], item = item, a[pos]
    return a

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
    print("cycle OK")


if __name__ == "__main__":
    main()
