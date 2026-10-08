"""Cosine similarity on bigram profiles

Cosine of character-bigram count vectors, in [0, 1].

What this IS: cosine similarity over bigram frequency profiles.

What this IS NOT:
* Jaccard/Dice -- those use sets, this uses counts.
* trigram based -- ed_41 uses trigrams and returns a distance.
"""

from __future__ import annotations

import ast
import math
from typing import Dict, List, Tuple

#: Module version.
ED_19_VERSION = "ed-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-19.v1"


def _profile(s: str, q: int) -> Dict[str, int]:
    d: Dict[str, int] = {}
    for i in range(len(s) - q + 1):
        g = s[i:i + q]
        d[g] = d.get(g, 0) + 1
    return d


def cosine_bigram(a: str, b: str) -> float:
    """Cosine similarity of bigram count vectors."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    A, B = _profile(a, 2), _profile(b, 2)
    if not A and not B:
        return 1.0 if a == b else 0.0
    if not A or not B:
        return 0.0
    dot = sum(c * B.get(g, 0) for g, c in A.items())
    na = math.sqrt(sum(c * c for c in A.values()))
    nb = math.sqrt(sum(c * c for c in B.values()))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)

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
    assert abs(cosine_bigram("abc", "abc") - 1.0) < 1e-9
    assert cosine_bigram("abc", "def") == 0.0
    assert cosine_bigram("", "abc") == 0.0
    assert 0.0 < cosine_bigram("night", "nacht") < 1.0
    assert abs(cosine_bigram("aaaa", "aa") - 1.0) < 1e-9
    try:
        cosine_bigram("a", 4)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("19-cosine-bigram OK")


if __name__ == "__main__":
    main()
