"""PriorityQueue: min-heap priority queue with FIFO tie-break, heap built on plain lists. IS: a min-priority queue; pop/peek on empty raise IndexError; equal priorities come out FIFO. IS NOT: a max-heap, a decrease-key handle, or a thread-safe queue."""

from __future__ import annotations

import ast
from typing import Any, List, Tuple
VERSION = "queue-05.v1"

def _req_priority(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("priority must be a real number")
    return float(value)


class PriorityQueue:
    """Min-heap of ``(priority, seq, item)``; ``seq`` breaks ties FIFO."""

    def __init__(self) -> None:
        self._h: List[Tuple[float, int, Any]] = []
        self._seq = 0

    def push(self, priority: object, item: Any) -> None:
        p = _req_priority(priority)
        entry = (p, self._seq, item)
        self._seq += 1
        self._h.append(entry)
        self._sift_up(len(self._h) - 1)

    def pop(self) -> Any:
        if not self._h:
            raise IndexError("pop from empty priority queue")
        top = self._h[0]
        last = self._h.pop()
        if self._h:
            self._h[0] = last
            self._sift_down(0)
        return top[2]

    def peek(self) -> Any:
        if not self._h:
            raise IndexError("peek from empty priority queue")
        return self._h[0][2]

    def is_empty(self) -> bool:
        return not self._h

    def __len__(self) -> int:
        return len(self._h)

    def _sift_up(self, i: int) -> None:
        h = self._h
        while i > 0:
            parent = (i - 1) // 2
            if h[i][:2] < h[parent][:2]:
                h[i], h[parent] = h[parent], h[i]
                i = parent
            else:
                break

    def _sift_down(self, i: int) -> None:
        h = self._h
        n = len(h)
        while True:
            left, right = 2 * i + 1, 2 * i + 2
            smallest = i
            if left < n and h[left][:2] < h[smallest][:2]:
                smallest = left
            if right < n and h[right][:2] < h[smallest][:2]:
                smallest = right
            if smallest == i:
                break
            h[i], h[smallest] = h[smallest], h[i]
            i = smallest


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
    pq = PriorityQueue()
    pq.push(2, "b"); pq.push(1, "a"); pq.push(3, "c")
    assert pq.peek() == "a" and len(pq) == 3
    assert pq.pop() == "a" and pq.pop() == "b" and pq.pop() == "c"
    assert pq.is_empty()
    pq.push(1, "x"); pq.push(1, "y")
    assert pq.pop() == "x" and pq.pop() == "y"  # FIFO tie-break
    try:
        pq.pop()
    except IndexError:
        pass
    else:
        raise AssertionError("pop on empty must raise IndexError")
    for bad in ("1", None, True):
        try:
            pq.push(bad, "z")
        except ValueError:
            pass
        else:
            raise AssertionError(f"priority {bad!r} must raise ValueError")
    assert stdlib_only()
    print("queue-05 OK: min-heap priority queue")


if __name__ == "__main__":
    main()
