"""Decode XORed array: rebuild arr from adjacent XORs.

Since encoded[i] = arr[i] ^ arr[i+1], XORing the running value with each code recovers the next element.

What this IS: the exact inverse of the XOR-difference encoding.
What this IS NOT: a cipher breaker; the first element is required.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_50_VERSION = "bit-decode-xor.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-decode-xor.v1"


class BitError(Exception):
    """Fail-closed."""


def decode_xor(encoded: list, first: int) -> list:
    """Decode XORed array: arr[i+1] = encoded[i] ^ arr[i]."""
    arr = [first]
    for e in encoded:
        arr.append(arr[-1] ^ e)
    return arr

def test_decode_basic():
    assert decode_xor([1, 2, 3], 1) == [1, 0, 2, 1]


def test_decode_long():
    assert decode_xor([6, 2, 7, 3], 4) == [4, 2, 0, 7, 4]


def test_decode_empty():
    assert decode_xor([], 9) == [9]


def test_decode_roundtrip():
    orig = [5, 1, 9, 3, 7]
    enc = [orig[i] ^ orig[i + 1] for i in range(len(orig) - 1)]
    assert decode_xor(enc, orig[0]) == orig

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
    test_decode_basic()
    test_decode_long()
    test_decode_empty()
    test_decode_roundtrip()
    assert stdlib_only()
    print("bit-50 OK: decode-xor")


if __name__ == "__main__":
    main()
