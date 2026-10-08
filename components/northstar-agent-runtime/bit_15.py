"""Toggle bit: flip bit i of n.

XOR with a single 1 at position i inverts exactly that bit.

What this IS: the flag-flipping primitive.
What this IS NOT: a set-or-clear; the old value decides the result.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_15_VERSION = "bit-toggle-bit.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-toggle-bit.v1"


class BitError(Exception):
    """Fail-closed."""


def toggle_bit(n: int, i: int) -> int:
    """Return n with bit i flipped."""
    if n < 0 or i < 0:
        raise BitError("bad args")
    return n ^ (1 << i)

def test_toggle_on_to_off():
    assert toggle_bit(0b1010, 1) == 0b1000


def test_toggle_off_to_on():
    assert toggle_bit(0b1000, 1) == 0b1010


def test_toggle_twice():
    assert toggle_bit(toggle_bit(0b1010, 3), 3) == 0b1010

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
    test_toggle_on_to_off()
    test_toggle_off_to_on()
    test_toggle_twice()
    assert stdlib_only()
    print("bit-15 OK: toggle-bit")


if __name__ == "__main__":
    main()
