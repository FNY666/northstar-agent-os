"""Zigzag conversion: row-bucket rail fence.

Walks characters across rows bouncing at the edges; O(n).

What this IS: a real O(n) conversion.
What this IS NOT: decoding the zigzag.
"""

from __future__ import annotations

import ast

#: Module version.
STR_35_VERSION = "str-zigzag.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-zigzag-conversion.v1"


class StrError(Exception):
    """Fail-closed."""


def zigzag_convert(s: str, rows: int) -> str:
    """Rail-fence (zigzag) conversion with the given row count."""
    if rows <= 1 or rows >= len(s):
        return s
    out = [""] * rows
    r, step = 0, 1
    for ch in s:
        out[r] += ch
        if r == 0:
            step = 1
        elif r == rows - 1:
            step = -1
        r += step
    return "".join(out)


def test_zigzag_known():
    assert zigzag_convert("PAYPALISHIRING", 3) == "PAHNAPLSIIGYIR"


def test_zigzag_four():
    assert zigzag_convert("PAYPALISHIRING", 4) == "PINALSIGYAHRPI"


def test_zigzag_one():
    assert zigzag_convert("ABC", 1) == "ABC"


def test_zigzag_empty():
    assert zigzag_convert("", 3) == ""


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
    test_zigzag_known()
    test_zigzag_four()
    test_zigzag_one()
    test_zigzag_empty()
    assert stdlib_only()
    print("str-35 OK: zigzag")


if __name__ == "__main__":
    main()
