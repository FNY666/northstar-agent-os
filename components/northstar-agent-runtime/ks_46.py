"""Bin packing (first-fit decreasing)

Pack items into the fewest bins of fixed capacity.

What this IS: first-fit-decreasing bin packing: a knapsack-like covering dual.

What this IS NOT:
* an exact bin packer -- FFD is a heuristic.
* a solver that splits items across bins.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_46_VERSION = "ks-46.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-46.v1"


def bin_packing_ffd(weights, capacity):
    # First-fit decreasing: pack items into fewest bins (mock heuristic).
    if capacity <= 0:
        raise ValueError("capacity must be > 0")
    bins = []
    for w in sorted(weights, reverse=True):
        if w < 0 or w > capacity:
            raise ValueError("item weight out of range")
        for i in range(len(bins)):
            if bins[i] + w <= capacity:
                bins[i] += w
                break
        else:
            bins.append(w)
    return len(bins)

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
    assert bin_packing_ffd([4, 8, 1, 4, 2, 1], 10) == 2
    assert bin_packing_ffd([], 10) == 0
    assert bin_packing_ffd([10, 10], 10) == 2
    assert bin_packing_ffd([1, 1, 1], 10) == 1
    assert stdlib_only()
    print("46-bin-packing OK")


if __name__ == "__main__":
    main()
