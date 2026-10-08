"""MinQueue: FIFO queue with O(1) amortized get_min via two min-tracking stacks. IS: a min-tracking queue; get_min/dequeue on empty raise IndexError. IS NOT: a max-tracking queue (see queue_29)."""

from __future__ import annotations

import ast
from typing import Any, List, Tuple
VERSION = "queue-28.v1"

def _req_number(x: object) -> float:
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        raise ValueError("queue items must be real numbers")
    return float(x)


class MinQueue:
    """Queue supporting ``get_min`` in O(1) amortized time."""

    def __init__(self) -> None:
        self._in: List[Tuple[float, float]] = []  # (value, min-so-far)
        self._out: List[Tuple[float, float]] = []

    def _push_in(self, x: float) -> None:
        cur = x if not self._in else min(x, self._in[-1][1])
        self._in.append((x, cur))

    def enqueue(self, item: object) -> None:
        self._push_in(_req_number(item))

    def _shift(self) -> None:
        if not self._out:
            while self._in:
                x, _ = self._in.pop()
                cur = x if not self._out else min(x, self._out[-1][1])
                self._out.append((x, cur))

    def dequeue(self) -> float:
        self._shift()
        if not self._out:
            raise IndexError("dequeue from empty queue")
        return self._out.pop()[0]

    def get_min(self) -> float:
        self._shift()
        if not self._out and not self._in:
            raise IndexError("get_min from empty queue")
        cands = []
        if self._in:
            cands.append(self._in[-1][1])
        if self._out:
            cands.append(self._out[-1][1])
        return min(cands)

    def is_empty(self) -> bool:
        return not self._in and not self._out

    def __len__(self) -> int:
        return len(self._in) + len(self._out)


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
    q = MinQueue()
    q.enqueue(3); q.enqueue(1); q.enqueue(2)
    assert q.get_min() == 1 and len(q) == 3
    assert q.dequeue() == 3 and q.get_min() == 1
    assert q.dequeue() == 1 and q.get_min() == 2
    q.enqueue(0)
    assert q.get_min() == 0
    try:
        MinQueue().get_min()
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
    print("queue-28 OK: O(1) min queue")


if __name__ == "__main__":
    main()
