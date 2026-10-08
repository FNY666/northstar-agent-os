"""Bogo sort (mock): shuffle until sorted; seeded and capped.

Repeatedly shuffles until the list happens to be sorted. Seeded RNG makes it deterministic; inputs longer than max_n are refused outright.

What this IS: an educational mock of the joke sort; correct on tiny inputs.

What this IS NOT:
* Expected O(n * n!) shuffles -- never use on real data.
* The cap is the only thing making this module safe.
"""

from __future__ import annotations

import ast
import random
from typing import List

#: Module version.
SORT_30_VERSION = "sort-30.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-30.v1"


def sort(data: List[int], max_n: int = 7, seed: int = 0) -> List[int]:
    # Bogo sort (educational mock): shuffle until sorted. Seeded for
    # determinism; refuses inputs larger than max_n.
    a = list(data)
    if len(a) > max_n:
        raise ValueError("bogo sort refuses inputs larger than %d" % max_n)
    rng = random.Random(seed)
    n = len(a)
    while any(a[i] > a[i + 1] for i in range(n - 1)):
        rng.shuffle(a)
    return a

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "random", "typing"}
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
    print("bogo OK")


if __name__ == "__main__":
    main()
