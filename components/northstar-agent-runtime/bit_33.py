"""Sign of integer: -1, 0, or 1 via arithmetic shift.

Shifting the sign bit down broadcasts it; OR with 1 maps zero/non-zero to the right sign.

What this IS: the branch-free signum for 32-bit ints.
What this IS NOT: a float sign; NaN and infinities are out of scope.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_33_VERSION = "bit-sign-of.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-sign-of.v1"


class BitError(Exception):
    """Fail-closed."""


def sign_of(n: int) -> int:
    """-1, 0, 1 via arithmetic shift; no if-branches."""
    if not -(2 ** 31) <= n < 2 ** 31:
        raise BitError("32-bit range required")
    return (n != 0) * (1 | (n >> 31))

def test_sign_positive():
    assert sign_of(10) == 1


def test_sign_negative():
    assert sign_of(-10) == -1


def test_sign_zero():
    assert sign_of(0) == 0


def test_sign_range_raises():
    try:
        sign_of(2 ** 40)
    except BitError:
        return
    raise AssertionError("expected BitError")

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
    test_sign_positive()
    test_sign_negative()
    test_sign_zero()
    test_sign_range_raises()
    assert stdlib_only()
    print("bit-33 OK: sign-of")


if __name__ == "__main__":
    main()
