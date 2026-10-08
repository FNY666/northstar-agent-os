"""Rod cutting (maximum revenue) via dynamic programming.

``prices[i]`` is the price of a rod of length i+1. Recurrence:

    r[j] = max over 1<=i<=j of prices[i-1] + r[j-i],   r[0] = 0

Bottom-up over rod lengths. Time O(n * len(prices)), space O(n).
``n`` must be non-negative; ``ValueError`` is raised otherwise.
"""

import ast
import sys
from pathlib import Path
from typing import List, Sequence

ALGO_48_VERSION = "algo-48.v1"

STDLIB_USED = frozenset({"ast", "pathlib", "sys", "typing"})


def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every imported top-level module
    is one this module actually uses from the standard library."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    stdlib_names = set(sys.stdlib_module_names)
    for name in sorted(imported):
        assert name in stdlib_names, "non-stdlib import: %s" % name
        assert name in STDLIB_USED, "imported but unused module: %s" % name
    assert set(STDLIB_USED) == imported, (
        "import drift: declared %s vs found %s"
        % (sorted(STDLIB_USED), sorted(imported))
    )
    return True


def rod_cutting(prices: Sequence[int], n: int) -> int:
    """Return the maximum revenue obtainable from a rod of length ``n``."""
    if n < 0:
        raise ValueError("n must be non-negative, got %r" % (n,))
    prices = list(prices)
    r: List[int] = [0] * (n + 1)
    for j in range(1, n + 1):
        best = 0
        for i in range(1, min(j, len(prices)) + 1):
            cand = prices[i - 1] + r[j - i]
            if cand > best:
                best = cand
        r[j] = best
    return r[n]


def main() -> None:
    prices = [1, 5, 8, 9, 10, 17, 17, 20]
    assert rod_cutting(prices, 4) == 10
    assert rod_cutting(prices, 8) == 22
    assert rod_cutting(prices, 0) == 0
    assert rod_cutting([], 5) == 0
    assert rod_cutting([5], 1) == 5
    assert rod_cutting([5], 3) == 15
    try:
        rod_cutting(prices, -2)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative n")
    assert stdlib_only()
    print("algo-48 OK")


if __name__ == "__main__":
    main()
