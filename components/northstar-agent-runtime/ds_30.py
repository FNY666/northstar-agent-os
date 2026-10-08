"""DS: Sqrt Decomposition (30/50). sqrt decomposition for range sums"""
from __future__ import annotations

import ast
import math

#: Module version.
DS_30_VERSION = "ds-30-sqrt-decomposition.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-30.sqrt-decomposition.v1"


class SqrtDecomp:
    """Sqrt decomposition: block sums for range-sum queries."""

    def __init__(self, data):
        self._arr = list(data)
        n = len(self._arr)
        self._bsize = max(1, int(math.isqrt(n)) if n else 1)
        nblocks = (n + self._bsize - 1) // self._bsize if n else 0
        self._blocks = [0] * nblocks
        for i, v in enumerate(self._arr):
            self._blocks[i // self._bsize] += v

    def update(self, index, value):
        if not 0 <= index < len(self._arr):
            raise IndexError("index out of range")
        self._blocks[index // self._bsize] += value - self._arr[index]
        self._arr[index] = value

    def query(self, left, right):
        """Sum over [left, right)."""
        n = len(self._arr)
        if not 0 <= left <= right <= n:
            raise ValueError("bad range")
        res = 0
        b = self._bsize
        while left < right and left % b != 0:
            res += self._arr[left]
            left += 1
        while left + b <= right:
            res += self._blocks[left // b]
            left += b
        while left < right:
            res += self._arr[left]
            left += 1
        return res

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "math"}
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
    sd = SqrtDecomp([1, 2, 3, 4, 5, 6, 7, 8, 9])
    assert sd.query(0, 9) == 45
    assert sd.query(2, 7) == 25
    sd.update(0, 10)
    assert sd.query(0, 9) == 54
    assert sd.query(0, 1) == 10
    assert stdlib_only()
    print("ds-30 OK: block sums, range queries")


if __name__ == "__main__":
    main()
