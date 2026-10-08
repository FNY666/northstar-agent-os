"""Burrows-Wheeler transform: reversible block permutation.

Naive rotation-sort BWT with the primary index; inverse rebuilds the rotation table.

What this IS: a real reversible BWT.
What this IS NOT: linear-time SA-based BWT.
"""

from __future__ import annotations

import ast

#: Module version.
STR_21_VERSION = "str-bwt.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-burrows-wheeler.v1"


class StrError(Exception):
    """Fail-closed."""


def bwt_transform(s: str):
    """Return (last_column, primary_index)."""
    if not s:
        return ("", 0)
    s2 = s + "\x00"
    rots = sorted(s2[i:] + s2[:i] for i in range(len(s2)))
    last = "".join(r[-1] for r in rots)
    return (last, rots.index(s2))


def bwt_inverse(last: str, idx: int) -> str:
    """Invert bwt_transform."""
    n = len(last)
    if n == 0:
        return ""
    table = [""] * n
    for _ in range(n):
        table = sorted([last[i] + table[i] for i in range(n)])
    return table[idx].rstrip("\x00")


def test_bwt_roundtrip():
    last, idx = bwt_transform("banana")
    assert bwt_inverse(last, idx) == "banana"


def test_bwt_empty():
    assert bwt_transform("") == ("", 0)
    assert bwt_inverse("", 0) == ""


def test_bwt_known():
    last, _ = bwt_transform("banana")
    assert sorted(last) == sorted("banana\x00")


def test_bwt_single():
    last, idx = bwt_transform("a")
    assert bwt_inverse(last, idx) == "a"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_bwt_roundtrip()
    test_bwt_empty()
    test_bwt_known()
    test_bwt_single()
    assert stdlib_only()
    print("str-21 OK: bwt")


if __name__ == "__main__":
    main()
