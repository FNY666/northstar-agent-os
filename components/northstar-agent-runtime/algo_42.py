"""0/1 knapsack via dynamic programming.

Recurrence over items, capacity tracked in a 1-D table scanned backwards:

    dp[w] = max(dp[w], dp[w - weights[i]] + values[i])

Each item is used at most once. Time O(n * capacity), space O(capacity).
Weights, values and capacity must be non-negative ints; ``ValueError`` is
raised otherwise.
"""

import ast
import sys
from pathlib import Path
from typing import List, Sequence

ALGO_42_VERSION = "algo-42.v1"

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


def knapsack(weights: Sequence[int], values: Sequence[int], capacity: int) -> int:
    """Return the maximum total value fitting in ``capacity`` (0/1 choice)."""
    if capacity < 0:
        raise ValueError("capacity must be non-negative, got %r" % (capacity,))
    weights = list(weights)
    values = list(values)
    if len(weights) != len(values):
        raise ValueError("weights and values must have the same length")
    for w in weights:
        if w < 0:
            raise ValueError("weights must be non-negative, got %r" % (w,))
    for v in values:
        if v < 0:
            raise ValueError("values must be non-negative, got %r" % (v,))
    dp: List[int] = [0] * (capacity + 1)
    for w, v in zip(weights, values):
        for c in range(capacity, w - 1, -1):
            cand = dp[c - w] + v
            if cand > dp[c]:
                dp[c] = cand
    return dp[capacity]


def main() -> None:
    assert knapsack([1, 3, 4, 5], [1, 4, 5, 7], 7) == 9
    assert knapsack([], [], 10) == 0
    assert knapsack([1, 2], [3, 4], 0) == 0
    assert knapsack([5], [10], 3) == 0
    assert knapsack([1, 2], [3, 4], 10) == 7
    assert knapsack([2, 2, 6], [6, 10, 12], 10) == 28
    try:
        knapsack([1], [1], -1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative capacity")
    assert stdlib_only()
    print("algo-42 OK")


if __name__ == "__main__":
    main()
