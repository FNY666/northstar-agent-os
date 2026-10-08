"""Huffman coding: optimal prefix code via heap.

Builds the optimal prefix tree with a min-heap; encodes to bits, decodes via reversed code table.

What this IS: a real Huffman codec.
What this IS NOT: canonical codes / bit-packed I/O.
"""

from __future__ import annotations

import ast
import heapq
from collections import Counter

#: Module version.
STR_19_VERSION = "str-huffman.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-huffman-coding.v1"


class StrError(Exception):
    """Fail-closed."""


class _HuffNode:
    __slots__ = ("ch", "freq", "left", "right")

    def __init__(self, ch, freq, left=None, right=None):
        self.ch = ch
        self.freq = freq
        self.left = left
        self.right = right

    def __lt__(self, other):
        return self.freq < other.freq


def build_huffman_codes(s: str) -> dict:
    """Return {char: bitstring} optimal prefix codes."""
    if not s:
        return {}
    heap = [_HuffNode(ch, f) for ch, f in Counter(s).items()]
    heapq.heapify(heap)
    if len(heap) == 1:
        return {heap[0].ch: "0"}
    while len(heap) > 1:
        a = heapq.heappop(heap)
        b = heapq.heappop(heap)
        heapq.heappush(heap, _HuffNode(None, a.freq + b.freq, a, b))
    codes = {}

    def walk(node, prefix):
        if node.ch is not None:
            codes[node.ch] = prefix or "0"
            return
        walk(node.left, prefix + "0")
        walk(node.right, prefix + "1")

    walk(heap[0], "")
    return codes


def huffman_encode(s: str):
    """Return (bitstring, codes)."""
    codes = build_huffman_codes(s)
    return "".join(codes[ch] for ch in s), codes


def huffman_decode(bits: str, codes: dict) -> str:
    """Decode a bitstring with the code table."""
    rev = {v: k for k, v in codes.items()}
    out = []
    cur = ""
    for bit in bits:
        cur += bit
        if cur in rev:
            out.append(rev[cur])
            cur = ""
    if cur:
        raise StrError("trailing bits")
    return "".join(out)


def test_huffman_roundtrip():
    bits, codes = huffman_encode("aaabbc")
    assert huffman_decode(bits, codes) == "aaabbc"


def test_huffman_prefix_free():
    codes = build_huffman_codes("aaabbbc")
    vals = list(codes.values())
    assert all(not (a != b and b.startswith(a)) for a in vals for b in vals)


def test_huffman_single():
    bits, codes = huffman_encode("zzzz")
    assert huffman_decode(bits, codes) == "zzzz"


def test_huffman_empty():
    assert build_huffman_codes("") == {}


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "collections", "heapq", "pathlib"}
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
    test_huffman_roundtrip()
    test_huffman_prefix_free()
    test_huffman_single()
    test_huffman_empty()
    assert stdlib_only()
    print("str-19 OK: huffman")


if __name__ == "__main__":
    main()
