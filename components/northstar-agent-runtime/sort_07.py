"""Shell sort (Shell gaps): original n/2, n/4, ... sequence.

Insertion sort generalized to gap-spaced subsequences, starting with gap n/2 and halving down to 1.

What this IS: Shell's original 1959 shell sort.

What this IS NOT:
* The n/2^k sequence is the weakest known gap sequence.
* Baseline for the Knuth and Ciura variants.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_07_VERSION = "sort-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-07.v1"


def sort(data: List[int]) -> List[int]:
    # Shell sort with Shell's original gap sequence: n/2, n/4, ..., 1.
    a = list(data)
    n = len(a)
    gap = n // 2
    while gap > 0:
        for i in range(gap, n):
            tmp = a[i]
            j = i
            while j >= gap and a[j - gap] > tmp:
                a[j] = a[j - gap]
                j -= gap
            a[j] = tmp
        gap //= 2
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
    print("shell-shell OK")


if __name__ == "__main__":
    main()
