"""KQueues: k independent FIFO queues sharing one fixed-size array via free-list chaining. IS: k array-backed queues; bad queue numbers raise ValueError, overflow raises OverflowError. IS NOT: k resizable queues or one queue with k priorities."""

from __future__ import annotations

import ast
from typing import Any, List
VERSION = "queue-30.v1"

class KQueues:
    """``k`` queues multiplexed over a single array of ``n`` slots."""

    def __init__(self, n: int, k: int) -> None:
        for name, v in (("n", n), ("k", k)):
            if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
                raise ValueError(f"{name} must be a positive int")
        if k > n:
            raise ValueError("k must not exceed n")
        self._n, self._k = n, k
        self._arr: List[Any] = [None] * n
        self._front: List[int] = [-1] * k
        self._rear: List[int] = [-1] * k
        self._next: List[int] = list(range(1, n)) + [-1]
        self._free = 0

    def _check_q(self, qnum: int) -> None:
        if isinstance(qnum, bool) or not isinstance(qnum, int) or not 0 <= qnum < self._k:
            raise ValueError(f"qnum must satisfy 0 <= qnum < {self._k}")

    def enqueue(self, qnum: int, item: Any) -> None:
        self._check_q(qnum)
        if self._free == -1:
            raise OverflowError("all queues full")
        slot = self._free
        self._free = self._next[slot]
        self._next[slot] = -1
        self._arr[slot] = item
        if self._front[qnum] == -1:
            self._front[qnum] = self._rear[qnum] = slot
        else:
            self._next[self._rear[qnum]] = slot
            self._rear[qnum] = slot

    def dequeue(self, qnum: int) -> Any:
        self._check_q(qnum)
        if self._front[qnum] == -1:
            raise IndexError(f"dequeue from empty queue {qnum}")
        slot = self._front[qnum]
        item = self._arr[slot]
        self._front[qnum] = self._next[slot]
        if self._front[qnum] == -1:
            self._rear[qnum] = -1
        self._next[slot] = self._free
        self._free = slot
        return item

    def is_empty(self, qnum: int) -> bool:
        self._check_q(qnum)
        return self._front[qnum] == -1


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
    kq = KQueues(6, 3)
    kq.enqueue(0, "a"); kq.enqueue(1, "b"); kq.enqueue(2, "c"); kq.enqueue(0, "d")
    assert kq.dequeue(0) == "a" and kq.dequeue(1) == "b"
    assert kq.dequeue(0) == "d" and kq.dequeue(2) == "c"
    assert kq.is_empty(0) and kq.is_empty(1) and kq.is_empty(2)
    try:
        kq.dequeue(0)
    except IndexError:
        pass
    else:
        raise AssertionError("dequeue on empty must raise IndexError")
    try:
        kq.enqueue(3, "x")
    except ValueError:
        pass
    else:
        raise AssertionError("bad qnum must raise ValueError")
    kq2 = KQueues(2, 2)
    kq2.enqueue(0, 1); kq2.enqueue(1, 2)
    try:
        kq2.enqueue(0, 3)
    except OverflowError:
        pass
    else:
        raise AssertionError("enqueue when full must raise OverflowError")
    try:
        KQueues(2, 3)
    except ValueError:
        pass
    else:
        raise AssertionError("k > n must raise ValueError")
    assert stdlib_only()
    print("queue-30 OK: k queues in one array")


if __name__ == "__main__":
    main()
