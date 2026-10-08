"""LCS length (bit-parallel)

What this IS: Hunt-Szymanski / Crochemore bit-vector LCS: O((|b|/w) * |a|) via Python big ints.

What this IS NOT:
* the classic DP -- see lcs_01 for the readable version.
* a reconstruction -- bit-parallel form yields length only.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_15_VERSION = "lcs-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-15.v1"


def lcs_bitset(a: str, b: str) -> int:
    # Bit-parallel LCS. masks[ch] has bit i set iff b[i] == ch.
    masks = {}
    for i, ch in enumerate(b):
        masks[ch] = masks.get(ch, 0) | (1 << i)
    dp = 0
    for ch in a:
        common = masks.get(ch, 0)
        x = common | dp
        dp = (dp << 1) | 1
        dp = x & ~(x - dp)
    return bin(dp).count("1")

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
    assert lcs_bitset("abcde", "ace") == 3
    assert lcs_bitset("", "abc") == 0
    assert lcs_bitset("abc", "abc") == 3
    assert lcs_bitset("abc", "def") == 0
    assert lcs_bitset("AGGTAB", "GXTXAYB") == 4
    assert lcs_bitset("a" * 200, "a" * 200) == 200
    assert stdlib_only()
    print("15-ok OK")


if __name__ == "__main__":
    main()
