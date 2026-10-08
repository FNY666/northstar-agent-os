"""Word break

Decide whether a string segments into dictionary words.

What this IS: knapsack over string positions: reachable cut points.

What this IS NOT:
* a spell checker -- this only tests segmentability.
* a segment enumerator -- use recovery variants to list cuts.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set, Tuple

#: Module version.
KS_21_VERSION = "ks-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ks-21.v1"


def word_break(s, words):
    # True iff s segments into words from the dict.
    ws = set(words)
    dp = [False] * (len(s) + 1)
    dp[0] = True
    for i in range(1, len(s) + 1):
        for j in range(i):
            if dp[j] and s[j:i] in ws:
                dp[i] = True
                break
    return dp[len(s)]

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
    assert word_break("leetcode", ["leet", "code"]) is True
    assert word_break("catsandog", ["cats", "dog", "sand", "and", "cat"]) is False
    assert word_break("", ["a"]) is True
    assert word_break("a", ["a"]) is True
    assert stdlib_only()
    print("21-word-break OK")


if __name__ == "__main__":
    main()
