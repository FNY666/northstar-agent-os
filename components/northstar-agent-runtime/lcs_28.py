"""LCS of permutations via LIS

What this IS: LCS of two permutations reduced to longest increasing subsequence: O(n log n).

What this IS NOT:
* general LCS -- see lcs_01 (this needs true permutations).
* LCIS -- see lcs_29 for the increasing variant.
"""

from __future__ import annotations

import ast
import bisect
#: Module version.
LCS_28_VERSION = "lcs-28.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-28.v1"


def lcs_permutation(p, q) -> int:
    # Map q's order to ranks, then the LCS is the LIS of p's rank sequence.
    pos = {v: i for i, v in enumerate(q)}
    seq = [pos[v] for v in p]
    piles = []
    for x in seq:
        i = bisect.bisect_left(piles, x)
        if i == len(piles):
            piles.append(x)
        else:
            piles[i] = x
    return len(piles)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "bisect"}
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
    assert lcs_permutation([0, 1, 2], [0, 1, 2]) == 3
    assert lcs_permutation([0, 1, 2], [2, 1, 0]) == 1
    assert lcs_permutation([2, 0, 1, 3], [0, 1, 2, 3]) == 3
    assert lcs_permutation([1, 0, 3, 2], [0, 1, 2, 3]) == 2
    assert lcs_permutation([], []) == 0
    assert stdlib_only()
    print("28-ok OK")


if __name__ == "__main__":
    main()
