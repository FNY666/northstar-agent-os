"""Find Median from Data Stream: maintain a running median with two heaps IS: a max-heap for the lower half and a min-heap for the upper half IS NOT: keeping a sorted list of all values"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-07.v1"

class MedianFinder:
    """Running median via two heaps.

    Fail-closed: ``add_num`` accepts only numbers, else :class:`ValueError`;
    ``find_median`` on empty data raises :class:`IndexError`.
    """

    def __init__(self) -> None:
        self._low = []   # max-heap via negation
        self._high = []  # min-heap

    def add_num(self, num) -> None:
        if isinstance(num, bool) or not isinstance(num, (int, float)):
            raise ValueError("num must be a number")
        if not self._low or num <= -self._low[0]:
            heapq.heappush(self._low, -num)
        else:
            heapq.heappush(self._high, num)
        if len(self._low) > len(self._high) + 1:
            heapq.heappush(self._high, -heapq.heappop(self._low))
        elif len(self._high) > len(self._low):
            heapq.heappush(self._low, -heapq.heappop(self._high))

    def find_median(self):
        if not self._low and not self._high:
            raise IndexError("no numbers added")
        if len(self._low) > len(self._high):
            return float(-self._low[0])
        return (-self._low[0] + self._high[0]) / 2.0

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
    mf = MedianFinder()
    mf.add_num(1)
    mf.add_num(2)
    assert mf.find_median() == 1.5
    mf.add_num(3)
    assert mf.find_median() == 2.0
    mf.add_num(4)
    assert mf.find_median() == 2.5
    try:
        MedianFinder().find_median()
    except IndexError:
        pass
    else:
        raise AssertionError("empty median must raise IndexError")
    try:
        mf.add_num("x")
    except ValueError:
        pass
    else:
        raise AssertionError("non-number must raise ValueError")
    assert stdlib_only()
    print("heap-07.v1 OK")


if __name__ == "__main__":
    main()
