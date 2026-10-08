"""MaxQueue: FIFO queue with O(1) amortized get_max via two max-tracking stacks. IS: a max-tracking queue; get_max/dequeue on empty raise IndexError. IS NOT: a min-tracking queue (see queue_28)."""

from __future__ import annotations

import ast
from typing import List, Tuple
VERSION = "queue-29.v1"

def _req_number(x: object) -> float:
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        raise ValueError("queue items must be real numbers")
    return float(x)


class MaxQueue:
    """Queue supporting ``get_max`` in O(1) amortized time."""

    def __init__(self) -> None:
        self._in: List[Tuple[float, float]] = []
        self._out: List[Tuple[float, float]] = []

    def enqueue(self, item: object) -> None:
        x = _req_number(item)
        cur = x if not self._in else max(x, self._in[-1][1])
        self._in.append((x, cur))

    def _shift(self) -> None:
        if not self._out:
            while self._in:
                x, _ = self._in.pop()
                cur = x if not self._out else max(x, self._out[-1][1])
                self._out.append((x, cur))

    def dequeue(self) -> float:
        self._shift()
        if not self._out:
            raise IndexError("dequeue from empty queue")
        return self._out.pop()[0]

    def get_max(self) -> float:
        self._shift()
        if not self._in and not self._out:
            raise IndexError("get_max from empty queue")
        cands = []
        if self._in:
            cands.append(self._in[-1][1])
        if self._out:
            cands.append(self._out[-1][1])
        return max(cands)

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
    q = MaxQueue()
    q.enqueue(3); q.enqueue(1); q.enqueue(5)
    assert q.get_max() == 5
    assert q.dequeue() == 3 and q.get_max() == 5
    assert q.dequeue() == 1 and q.get_max() == 5
    assert q.dequeue() == 5
    try:
        q.get_max()
    except IndexError:
        pass
    else:
        raise AssertionError("get_max on empty must raise IndexError")
    try:
        q.dequeue()
    except IndexError:
        pass
    else:
        raise AssertionError("dequeue on empty must raise IndexError")
    assert stdlib_only()
    print("queue-29 OK: O(1) max queue")


if __name__ == "__main__":
    main()
