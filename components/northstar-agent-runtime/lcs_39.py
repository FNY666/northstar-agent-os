"""Maximum suffix/prefix overlap

What this IS: longest k with suffix(a, k) == prefix(b, k): the assembly overlap.

What this IS NOT:
* longest common substring -- see lcs_05 (overlap is anchored).
* general alignment -- see lcs_37.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_39_VERSION = "lcs-39.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-39.v1"


def max_overlap(a: str, b: str) -> int:
    # Try every overlap length from large to small.
    best = 0
    for k in range(1, min(len(a), len(b)) + 1):
        if a[-k:] == b[:k]:
            best = k
    return best

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
    assert max_overlap("abcde", "cdefg") == 3
    assert max_overlap("abc", "def") == 0
    assert max_overlap("abc", "abc") == 3
    assert max_overlap("", "a") == 0
    assert max_overlap("abab", "abab") == 4
    assert stdlib_only()
    print("39-ok OK")


if __name__ == "__main__":
    main()
