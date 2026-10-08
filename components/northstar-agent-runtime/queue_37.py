"""MinMaxQueue: FIFO queue with O(1) amortized get_min and get_max via monotone deques. IS: a min/max-tracking queue; queries on empty raise IndexError. IS NOT: a double-ended priority queue with deletions by value."""

from __future__ import annotations

import ast
from collections import deque
from typing import List
VERSION = "queue-37.v1"

def _req_number(x: object) -> float:
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        raise ValueError("queue items must be real numbers")
    return float(x)


class MinMaxQueue:
    """Queue with amortized O(1) ``get_min`` and ``get_max``."""

    def __init__(self) -> None:
        self._q: deque = deque()
        self._mins: deque = deque()
        self._maxs: deque = deque()

    def enqueue(self, item: object) -> None:
        x = _req_number(item)
        self._q.append(x)
        while self._mins and self._mins[-1] > x:
            self._mins.pop()
        self._mins.append(x)
        while self._maxs and self._maxs[-1] < x:
            self._maxs.pop()
        self._maxs.append(x)

    def dequeue(self) -> float:
        if not self._q:
            raise IndexError("dequeue from empty queue")
        x = self._q.popleft()
        if self._mins[0] == x:
            self._mins.popleft()
        if self._maxs[0] == x:
            self._maxs.popleft()
        return x

    def get_min(self) -> float:
        if not self._q:
            raise IndexError("get_min from empty queue")
        return self._mins[0]

    def get_max(self) -> float:
        if not self._q:
            raise IndexError("get_max from empty queue")
        return self._maxs[0]

    def is_empty(self) -> bool:
        return not self._q

    def __len__(self) -> int:
        return len(self._q)


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
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
    q = MinMaxQueue()
    q.enqueue(3); q.enqueue(1); q.enqueue(2)
    assert q.get_min() == 1 and q.get_max() == 3
    assert q.dequeue() == 3
    assert q.get_min() == 1 and q.get_max() == 2
    q.enqueue(0)
    assert q.get_min() == 0 and q.get_max() == 2
    try:
        MinMaxQueue().get_min()
    except IndexError:
        pass
    else:
        raise AssertionError("get_min on empty must raise IndexError")
    try:
        q.enqueue("x")
    except ValueError:
        pass
    else:
        raise AssertionError("non-numeric item must raise ValueError")
    assert stdlib_only()
    print("queue-37 OK: min/max queue")


if __name__ == "__main__":
    main()
