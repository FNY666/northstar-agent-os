"""Bag distance

Multiset difference size between character bags.

What this IS: max(|A-B|, |B-A|) over character multisets.

What this IS NOT:
* Hamming -- order is ignored here.
* q-gram -- ed_30 works on substrings, not single chars.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_42_VERSION = "ed-42.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-42.v1"


def _counts(s: str) -> Dict[str, int]:
    d: Dict[str, int] = {}
    for c in s:
        d[c] = d.get(c, 0) + 1
    return d


def bag_distance(a: str, b: str) -> int:
    """Bag distance: max multiset difference between character bags."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    A, B = _counts(a), _counts(b)
    ab = sum(max(0, A.get(c, 0) - B.get(c, 0)) for c in A)
    ba = sum(max(0, B.get(c, 0) - A.get(c, 0)) for c in B)
    return max(ab, ba)

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
    assert bag_distance("abc", "cba") == 0
    assert bag_distance("a", "ab") == 1
    assert bag_distance("abc", "abc") == 0
    assert bag_distance("", "abc") == 3
    assert bag_distance("aab", "abb") == 1
    try:
        bag_distance("a", 1)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("42-bag OK")


if __name__ == "__main__":
    main()
