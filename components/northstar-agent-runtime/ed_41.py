"""Trigram cosine distance

One minus the cosine similarity of trigram count vectors.

What this IS: 1 - cosine over trigram profiles; 0.0 means identical.

What this IS NOT:
* bigram cosine -- ed_19 uses q=2 and returns a similarity.
* Jaccard -- counts and normalization differ.
"""

from __future__ import annotations

import ast
import math
from typing import Dict, List, Tuple

#: Module version.
ED_41_VERSION = "ed-41.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-41.v1"


def _profile(s: str, q: int) -> Dict[str, int]:
    d: Dict[str, int] = {}
    for i in range(len(s) - q + 1):
        g = s[i:i + q]
        d[g] = d.get(g, 0) + 1
    return d


def trigram_cosine_distance(a: str, b: str) -> float:
    """1 - cosine similarity of trigram count vectors."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    A, B = _profile(a, 3), _profile(b, 3)
    if not A and not B:
        return 0.0
    if not A or not B:
        return 1.0
    dot = sum(c * B.get(g, 0) for g, c in A.items())
    na = math.sqrt(sum(c * c for c in A.values()))
    nb = math.sqrt(sum(c * c for c in B.values()))
    if na == 0.0 or nb == 0.0:
        return 1.0
    return 1.0 - dot / (na * nb)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "math"}
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
    assert trigram_cosine_distance("abc", "abc") == 0.0
    assert trigram_cosine_distance("abc", "def") == 1.0
    assert trigram_cosine_distance("", "") == 0.0
    assert trigram_cosine_distance("", "abc") == 1.0
    assert 0.0 < trigram_cosine_distance("night", "nacht") < 1.0
    try:
        trigram_cosine_distance("a", 2)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("41-trigram-cosine OK")


if __name__ == "__main__":
    main()
