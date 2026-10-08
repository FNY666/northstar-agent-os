"""Adjacent-swap (Kendall) distance

Minimum adjacent swaps to transform one string into another.

What this IS: the inversion count between matched positions; inputs must be anagrams.

What this IS NOT:
* a general edit distance -- insert/delete/substitute are forbidden.
* defined for non-anagrams -- that raises ValueError.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_22_VERSION = "ed-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-22.v1"


def adjacent_swap_distance(a: str, b: str) -> int:
    """Minimum number of adjacent swaps (inputs must be anagrams)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if sorted(a) != sorted(b):
        raise ValueError("strings must share the same character multiset")
    pos: Dict[str, List[int]] = {}
    for i, ch in enumerate(b):
        pos.setdefault(ch, []).append(i)
    ptr: Dict[str, int] = {ch: 0 for ch in pos}
    perm = []
    for ch in a:
        lst = pos[ch]
        p = ptr[ch]
        ptr[ch] = p + 1
        perm.append(lst[p])
    inv = 0
    for i in range(len(perm)):
        pi = perm[i]
        for j in range(i + 1, len(perm)):
            if pi > perm[j]:
                inv += 1
    return inv

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
    assert adjacent_swap_distance("abcd", "acbd") == 1
    assert adjacent_swap_distance("abc", "abc") == 0
    assert adjacent_swap_distance("ba", "ab") == 1
    assert adjacent_swap_distance("cba", "abc") == 3
    try:
        adjacent_swap_distance("ab", "ac")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("22-adjacent-swap OK")


if __name__ == "__main__":
    main()
