"""Bipartite graph6-like encoding.

What this IS: encodes the biadjacency matrix as a bit string, fail-closed on bad input
What this IS NOT: graph6; a simple row-major bit encoding
"""

from __future__ import annotations

import ast

#: Module version.
BIP_47_VERSION = "bip-encoding.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-encoding.v1"


class BipError(Exception):
    """Fail-closed."""



def encode_bits(n_left: int, n_right: int, edges: list) -> str:
    m = [[0] * n_right for _ in range(n_left)]
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        m[u][v] = 1
    return "".join(str(b) for row in m for b in row)


def decode_bits(n_left: int, n_right: int, bits: str) -> list:
    if len(bits) != n_left * n_right or any(c not in "01" for c in bits):
        raise BipError("bad bit string")
    edges = []
    for u in range(n_left):
        for v in range(n_right):
            if bits[u * n_right + v] == "1":
                edges.append((u, v))
    return edges


def test_enc_roundtrip():
    e = [(0, 0), (1, 2)]
    assert decode_bits(2, 3, encode_bits(2, 3, e)) == e


def test_enc_empty():
    assert encode_bits(2, 2, []) == "0000"


def test_enc_full():
    assert encode_bits(1, 2, [(0, 0), (0, 1)]) == "11"


def test_enc_bad():
    try:
        decode_bits(1, 1, "012")
    except BipError:
        return
    raise AssertionError("expected BipError")



def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "collections", "heapq", "itertools", "functools", "math"}
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
    test_enc_roundtrip()
    test_enc_empty()
    test_enc_full()
    test_enc_bad()
    assert stdlib_only()
    print("bip-47 OK: encoding")


if __name__ == "__main__":
    main()
