"""Kth Largest Element in a Stream: track the k-th largest value of a stream with a min-heap IS: a fixed-size min-heap whose root is the k-th largest IS NOT: re-sorting the whole stream on every add"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-08.v1"

class KthLargest:
    """K-th largest element of a stream.

    Fail-closed: ``k >= 1`` int and numeric initial values / adds,
    else :class:`ValueError`.
    """

    def __init__(self, k, nums) -> None:
        if isinstance(k, bool) or not isinstance(k, int) or k < 1:
            raise ValueError("k must be a positive int")
        if not isinstance(nums, list):
            raise ValueError("nums must be a list")
        self._k = k
        self._heap = []
        for x in nums:
            self.add(x)

    def add(self, val):
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise ValueError("val must be a number")
        if len(self._heap) < self._k:
            heapq.heappush(self._heap, val)
        elif val > self._heap[0]:
            heapq.heapreplace(self._heap, val)
        return self._heap[0]

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "heapq", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    kl = KthLargest(3, [4, 5, 8, 2])
    assert kl.add(3) == 4
    assert kl.add(5) == 5
    assert kl.add(10) == 5
    assert kl.add(9) == 8
    assert kl.add(4) == 8
    try:
        KthLargest(0, [1])
    except ValueError:
        pass
    else:
        raise AssertionError("k=0 must raise ValueError")
    try:
        kl.add("x")
    except ValueError:
        pass
    else:
        raise AssertionError("non-number add must raise ValueError")
    assert stdlib_only()
    print("heap-08.v1 OK")


if __name__ == "__main__":
    main()
