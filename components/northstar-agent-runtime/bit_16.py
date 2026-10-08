"""Update bit: write 0 or 1 into bit i of n.

Clears the target bit first, then ORs the new value shifted into place.

What this IS: the validated single-bit writer.
What this IS NOT: a multi-bit field writer; use one call per bit.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_16_VERSION = "bit-update-bit.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-update-bit.v1"


class BitError(Exception):
    """Fail-closed."""


def update_bit(n: int, i: int, v: int) -> int:
    """Return n with bit i set to v (0 or 1)."""
    if n < 0 or i < 0 or v not in (0, 1):
        raise BitError("bad args")
    return (n & ~(1 << i)) | (v << i)

def test_update_to_zero():
    assert update_bit(0b1010, 1, 0) == 0b1000


def test_update_to_one():
    assert update_bit(0b1000, 1, 1) == 0b1010


def test_update_bad_value_raises():
    try:
        update_bit(0b1010, 1, 2)
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
    test_update_to_zero()
    test_update_to_one()
    test_update_bad_value_raises()
    assert stdlib_only()
    print("bit-16 OK: update-bit")


if __name__ == "__main__":
    main()
