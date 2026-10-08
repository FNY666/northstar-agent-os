"""Roman numerals: bidirectional 1..3999 codec.

Greedy table for int->roman; right-to-left subtractive scan for roman->int.

What this IS: a real codec.
What this IS NOT: validation of non-canonical numerals.
"""

from __future__ import annotations

import ast

#: Module version.
STR_47_VERSION = "str-roman.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-roman-numerals.v1"


class StrError(Exception):
    """Fail-closed."""


_ROMAN = [(1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"),
            (90, "XC"), (50, "L"), (40, "XL"), (10, "X"), (9, "IX"),
            (5, "V"), (4, "IV"), (1, "I")]


def int_to_roman(n: int) -> str:
    """Convert 1..3999 to Roman numerals."""
    if not 1 <= n <= 3999:
        raise StrError("range 1..3999")
    out = []
    for v, sym in _ROMAN:
        while n >= v:
            out.append(sym)
            n -= v
    return "".join(out)


def roman_to_int(s: str) -> int:
    """Convert Roman numerals to int."""
    val = {"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}
    total = 0
    prev = 0
    for ch in reversed(s):
        if ch not in val:
            raise StrError("bad numeral")
        cur = val[ch]
        if cur < prev:
            total -= cur
        else:
            total += cur
        prev = cur
    return total


def test_roman_known():
    assert int_to_roman(1994) == "MCMXCIV"
    assert roman_to_int("MCMXCIV") == 1994


def test_roman_roundtrip():
    for n in (1, 4, 9, 58, 999, 2026, 3999):
        assert roman_to_int(int_to_roman(n)) == n


def test_roman_range():
    try:
        int_to_roman(0)
    except StrError:
        return
    raise AssertionError("expected StrError")


def test_roman_bad():
    try:
        roman_to_int("ABC")
    except StrError:
        return
    raise AssertionError("expected StrError")


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
    test_roman_known()
    test_roman_roundtrip()
    test_roman_range()
    test_roman_bad()
    assert stdlib_only()
    print("str-47 OK: roman")


if __name__ == "__main__":
    main()
