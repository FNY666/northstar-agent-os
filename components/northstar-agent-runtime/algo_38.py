"""Huffman coding: optimal prefix-free compression.

build_huffman(text) counts character frequencies, builds the Huffman
tree by repeatedly merging the two least-frequent nodes (using a
simple sorted list as the priority queue), and derives a
character->bitstring code map by walking the tree.

encode(text, codes) concatenates the bitstrings; decode(bits, root)
walks the tree bit by bit, emitting a character at each leaf.

Complexities: build O(k log k) with a heap over k distinct chars
(here O(k^2) with a sorted list, k = distinct chars, fine for the
mock scale), encode/decode O(len(text) * code length).

Edge cases: empty text -> ({}, None); a single distinct character
gets the code "0".
"""

from __future__ import annotations

import ast
import sys
from collections import Counter
from typing import Dict, List, Optional, Tuple

ALGO_38_VERSION = "algo-38.v1"


class _Node:
    __slots__ = ("freq", "char", "left", "right")

    def __init__(
        self,
        freq: int,
        char: Optional[str] = None,
        left: Optional["_Node"] = None,
        right: Optional["_Node"] = None,
    ) -> None:
        self.freq = freq
        self.char = char
        self.left = left
        self.right = right

    def is_leaf(self) -> bool:
        return self.char is not None


def build_huffman(text: str) -> Tuple[Dict[str, str], Optional[_Node]]:
    """Return (codes dict char->bitstring, tree root)."""
    freq = Counter(text)
    if not freq:
        return {}, None
    nodes: List[_Node] = [_Node(count, ch) for ch, count in freq.items()]
    nodes.sort(key=lambda n: (n.freq, n.char or ""))
    while len(nodes) > 1:
        a = nodes.pop(0)
        b = nodes.pop(0)
        merged = _Node(a.freq + b.freq, None, a, b)
        # Keep the list sorted (stable insertion by freq).
        idx = 0
        while idx < len(nodes) and nodes[idx].freq < merged.freq:
            idx += 1
        nodes.insert(idx, merged)
    root = nodes[0]
    codes: Dict[str, str] = {}

    def walk(node: _Node, prefix: str) -> None:
        if node.is_leaf():
            codes[node.char] = prefix or "0"  # single-char text case
            return
        walk(node.left, prefix + "0")  # type: ignore[union-attr]
        walk(node.right, prefix + "1")  # type: ignore[union-attr]

    walk(root, "")
    return codes, root


def encode(text: str, codes: Dict[str, str]) -> str:
    """Encode text as a bitstring using codes."""
    return "".join(codes[ch] for ch in text)


def decode(bits: str, root: Optional[_Node]) -> str:
    """Decode a bitstring back to text using the Huffman tree."""
    if root is None:
        if bits:
            raise ValueError("cannot decode bits with an empty tree")
        return ""
    if root.is_leaf():
        # Single distinct char: one code word per bit.
        return (root.char or "") * len(bits)
    out: List[str] = []
    node = root
    for b in bits:
        node = node.left if b == "0" else node.right
        if node is None:
            raise ValueError("invalid bitstring for this tree")
        if node.is_leaf():
            out.append(node.char or "")
            node = root
    if node is not root:
        raise ValueError("truncated bitstring")
    return "".join(out)


def stdlib_only() -> bool:
    """Assert every imported top-level module is from the stdlib."""
    src = open(__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in stdlib, node.module
    return True


def main() -> None:
    text = "this is an example of a huffman tree"
    codes, root = build_huffman(text)
    assert set(codes) == set(text)
    # Prefix-free: no code is a prefix of another.
    sorted_codes = sorted(codes.values())
    for i, c in enumerate(sorted_codes):
        for other in sorted_codes[i + 1:]:
            assert not other.startswith(c)
    bits = encode(text, codes)
    assert set(bits) <= {"0", "1"}
    assert decode(bits, root) == text
    # Single distinct character.
    codes1, root1 = build_huffman("aaaa")
    assert codes1 == {"a": "0"}
    assert decode(encode("aaaa", codes1), root1) == "aaaa"
    # Empty text.
    codes0, root0 = build_huffman("")
    assert codes0 == {} and root0 is None
    assert encode("", codes0) == ""
    assert decode("", root0) == ""
    assert stdlib_only()
    print("algo_38 OK")


if __name__ == "__main__":
    main()
