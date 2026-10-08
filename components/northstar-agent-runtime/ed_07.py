"""Weighted Levenshtein distance

Levenshtein with caller-supplied insert/delete/substitute costs.

What this IS: unit Levenshtein generalized to float operation costs.

What this IS NOT:
* the unit-cost version -- ed_01 fixes every cost at 1.
* an affine-gap model -- ed_09/ed_38 handle gap open/extend.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_07_VERSION = "ed-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-07.v1"


def weighted_levenshtein(
    a: str,
    b: str,
    insert_cost: float = 1.0,
    delete_cost: float = 1.0,
    substitute_cost: float = 1.0,
) -> float:
    """Levenshtein with custom operation costs."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    for name, c in (("insert", insert_cost), ("delete", delete_cost),
                    ("substitute", substitute_cost)):
        if c < 0:
            raise ValueError(name + " cost must be >= 0")
    m, n = len(a), len(b)
    prev = [j * insert_cost for j in range(n + 1)]
    for i in range(1, m + 1):
        cur = [i * delete_cost] + [0.0] * n
        ai = a[i - 1]
        for j in range(1, n + 1):
            sub = 0.0 if ai == b[j - 1] else substitute_cost
            cur[j] = min(prev[j] + delete_cost,
                         cur[j - 1] + insert_cost,
                         prev[j - 1] + sub)
        prev = cur
    return prev[n]

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
    assert weighted_levenshtein("kitten", "sitting") == 3.0
    assert weighted_levenshtein("a", "b", substitute_cost=2.0) == 2.0
    assert weighted_levenshtein("", "abc", insert_cost=0.5) == 1.5
    assert weighted_levenshtein("abc", "abc") == 0.0
    try:
        weighted_levenshtein("a", "b", insert_cost=-1.0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("07-weighted OK")


if __name__ == "__main__":
    main()
