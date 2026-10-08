"""Get bit: read bit i of n.

Right-shifts position i into the units place and masks with 1.

What this IS: the bounds-checked bit reader other modules build on.
What this IS NOT: a slice; it reads exactly one bit.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_12_VERSION = "bit-get-bit.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-get-bit.v1"


class BitError(Exception):
    """Fail-closed."""


def get_bit(n: int, i: int) -> int:
    """Return bit i of n (0 or 1)."""
    if n < 0 or i < 0:
        raise BitError("bad args")
    return (n >> i) & 1

def test_get_set():
    assert get_bit(0b1010, 1) == 1


def test_get_clear():
    assert get_bit(0b1010, 0) == 0


def test_get_high():
    assert get_bit(0b1010, 3) == 1


def test_get_bad_raises():
    try:
        get_bit(5, -1)
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
    test_get_set()
    test_get_clear()
    test_get_high()
    test_get_bad_raises()
    assert stdlib_only()
    print("bit-12 OK: get-bit")


if __name__ == "__main__":
    main()
