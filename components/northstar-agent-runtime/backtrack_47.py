"""Backtracking: Gray code generation -- produce an n-bit Gray code sequence
where consecutive values differ in exactly one bit.

IS: recursive construction (reflect-and-prefix: G(n) = 0·G(n-1) followed by
1·reverse(G(n-1))), which is the depth-first order of the hypercube
Hamiltonian path from 0.
IS NOT: balanced/adjacent-cyclic variants, binary-reflected vs. other Gray
encodings, or minimal-change orderings of non-binary alphabets.
"""

from __future__ import annotations

VERSION = "backtrack_47.v1"


import ast
from typing import List

_ALLOWED_IMPORTS = {"__future__", "ast", "typing", "dataclasses", "itertools",
                    "functools", "collections", "math", "re", "string", "sys"}


def gray_code(n: int) -> List[int]:
    """Return the n-bit Gray code sequence starting at 0."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return [0]
    prev = gray_code(n - 1)
    high_bit = 1 << (n - 1)
    return prev + [high_bit | x for x in reversed(prev)]


def _single_bit_diff(a: int, b: int) -> bool:
    d = a ^ b
    return d != 0 and (d & (d - 1)) == 0


def stdlib_only() -> bool:
    """Return True only if every import in this file comes from the allowed stdlib set."""
    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.module.split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert gray_code(0) == [0]
    assert gray_code(1) == [0, 1]
    assert gray_code(2) == [0, 1, 3, 2]
    assert gray_code(3) == [0, 1, 3, 2, 6, 7, 5, 4]
    seq = gray_code(4)
    assert len(seq) == 16 and len(set(seq)) == 16
    assert all(_single_bit_diff(seq[i], seq[i + 1]) for i in range(len(seq) - 1))
    assert gray_code(5)[0] == 0 and len(gray_code(5)) == 32
    print("backtrack_47 OK")


if __name__ == "__main__":
    main()
