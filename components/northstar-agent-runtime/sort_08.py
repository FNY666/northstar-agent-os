"""Shell sort (Knuth gaps): gaps (3^k - 1) / 2.

Shell sort using Knuth's gap sequence 1, 4, 13, 40, ... which avoids the even-gap interactions of Shell's original sequence.

What this IS: shell sort with a theoretically motivated gap sequence; O(n^(3/2)) worst case.

What this IS NOT:
* Not the empirically best sequence (see Ciura).
* Still a h-sort cascade, not a different algorithm.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_08_VERSION = "sort-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-08.v1"


def _gaps(n: int) -> List[int]:
    gaps = []
    g = 1
    while g < n:
        gaps.append(g)
        g = 3 * g + 1
    return gaps[::-1]


def sort(data: List[int]) -> List[int]:
    # Shell sort with Knuth's gap sequence: (3^k - 1) / 2.
    a = list(data)
    n = len(a)
    for gap in _gaps(n):
        for i in range(gap, n):
            tmp = a[i]
            j = i
            while j >= gap and a[j - gap] > tmp:
                a[j] = a[j - gap]
                j -= gap
            a[j] = tmp
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
    print("shell-knuth OK")


if __name__ == "__main__":
    main()
