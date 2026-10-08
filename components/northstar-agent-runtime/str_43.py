"""Add binary strings: bitwise addition.

Right-to-left add with carry; O(max(m,n)).

What this IS: a real implementation.
What this IS NOT: arbitrary-base addition.
"""

from __future__ import annotations

import ast

#: Module version.
STR_43_VERSION = "str-add-binary.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-add-binary.v1"


class StrError(Exception):
    """Fail-closed."""


def add_binary(a: str, b: str) -> str:
    """Add two binary strings."""
    i, j = len(a) - 1, len(b) - 1
    carry = 0
    out = []
    while i >= 0 or j >= 0 or carry:
        if i >= 0:
            carry += ord(a[i]) - 48
            i -= 1
        if j >= 0:
            carry += ord(b[j]) - 48
            j -= 1
        out.append("1" if carry % 2 else "0")
        carry //= 2
    return "".join(reversed(out))


def test_ab_basic():
    assert add_binary("11", "1") == "100"


def test_ab_carry():
    assert add_binary("1010", "1011") == "10101"


def test_ab_zero():
    assert add_binary("0", "0") == "0"


def test_ab_uneven():
    assert add_binary("1", "111") == "1000"


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
    test_ab_basic()
    test_ab_carry()
    test_ab_zero()
    test_ab_uneven()
    assert stdlib_only()
    print("str-43 OK: add-binary")


if __name__ == "__main__":
    main()
