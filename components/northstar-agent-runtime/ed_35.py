"""Unicode-normalized Levenshtein

Levenshtein after NFKD normalization with diacritics stripped.

What this IS: NFKD decompose + drop combining marks, then unit Levenshtein.

What this IS NOT:
* raw Unicode -- 'e' and combining-acute sequences compare equal here.
* case folding -- combine with ed_34 if you need both.
"""

from __future__ import annotations

import ast
import unicodedata
from typing import Dict, List, Tuple

#: Module version.
ED_35_VERSION = "ed-35.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-35.v1"


def _strip(s: str) -> str:
    nk = unicodedata.normalize("NFKD", s)
    return "".join(c for c in nk if not unicodedata.combining(c))


def _lev(a: str, b: str) -> int:
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        ai = a[i - 1]
        for j in range(1, n + 1):
            cost = 0 if ai == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[n]


def unicode_levenshtein(a: str, b: str) -> int:
    """Levenshtein after NFKD normalization and diacritic stripping."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    return _lev(_strip(a), _strip(b))

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "unicodedata"}
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
    assert unicode_levenshtein("caf\u00e9", "cafe") == 0
    assert unicode_levenshtein("na\u00efve", "naive") == 0
    assert unicode_levenshtein("abc", "abc") == 0
    assert unicode_levenshtein("abc", "abd") == 1
    try:
        unicode_levenshtein("a", 3)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("35-unicode OK")


if __name__ == "__main__":
    main()
