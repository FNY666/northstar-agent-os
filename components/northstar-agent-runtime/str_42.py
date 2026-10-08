"""Multiply strings: grade-school decimal multiplication.

Digit-by-digit products into a result array; handles '0' and strips leading zeros.

What this IS: a real O(m*n) implementation.
What this IS NOT: Karatsuba for huge inputs.
"""

from __future__ import annotations

import ast

#: Module version.
STR_42_VERSION = "str-multiply.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-multiply-strings.v1"


class StrError(Exception):
    """Fail-closed."""


def multiply_strings(a: str, b: str) -> str:
    """Multiply non-negative integer strings."""
    if a == "0" or b == "0":
        return "0"
    m, n = len(a), len(b)
    res = [0] * (m + n)
    for i in range(m - 1, -1, -1):
        for j in range(n - 1, -1, -1):
            p = res[i + j + 1] + (ord(a[i]) - 48) * (ord(b[j]) - 48)
            res[i + j + 1] = p % 10
            res[i + j] += p // 10
    return "".join(map(str, res)).lstrip("0") or "0"


def test_mul_basic():
    assert multiply_strings("123", "456") == "56088"


def test_mul_zero():
    assert multiply_strings("0", "999") == "0"


def test_mul_one():
    assert multiply_strings("1", "999") == "999"


def test_mul_big():
    assert multiply_strings("99", "99") == "9801"


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
    test_mul_basic()
    test_mul_zero()
    test_mul_one()
    test_mul_big()
    assert stdlib_only()
    print("str-42 OK: multiply")


if __name__ == "__main__":
    main()
