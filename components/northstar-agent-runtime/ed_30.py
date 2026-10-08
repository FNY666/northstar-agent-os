"""Q-gram distance

Multiset symmetric difference of character q-grams.

What this IS: sum over q-grams of |count_a - count_b| (default q=2).

What this IS NOT:
* set-based Jaccard/Dice -- counts matter here.
* cosine -- ed_19/ed_41 normalize by vector length.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_30_VERSION = "ed-30.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-30.v1"


def qgram_distance(a: str, b: str, q: int = 2) -> int:
    """Q-gram distance: L1 difference of q-gram count profiles."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if not isinstance(q, int) or q < 1:
        raise ValueError("q must be a positive int")
    ca: Dict[str, int] = {}
    cb: Dict[str, int] = {}
    for i in range(len(a) - q + 1):
        g = a[i:i + q]
        ca[g] = ca.get(g, 0) + 1
    for i in range(len(b) - q + 1):
        g = b[i:i + q]
        cb[g] = cb.get(g, 0) + 1
    return sum(abs(ca.get(g, 0) - cb.get(g, 0)) for g in set(ca) | set(cb))

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
    assert qgram_distance("abc", "abc") == 0
    assert qgram_distance("ab", "ba") == 2
    assert qgram_distance("aaaa", "aa") == 2
    assert qgram_distance("abc", "abc", q=3) == 0
    try:
        qgram_distance("a", "b", q=0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("30-qgram OK")


if __name__ == "__main__":
    main()
