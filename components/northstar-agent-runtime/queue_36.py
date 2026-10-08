"""PriorityQueueAging: priority queue where waiting items age (priority improves) on every pop. IS: an aging min-priority queue; pop/peek on empty raise IndexError. IS NOT: a starvation-free real-time scheduler (this is the mechanism, not the policy)."""

from __future__ import annotations

import ast
from typing import Any, List, Tuple
VERSION = "queue-36.v1"

def _req_priority(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("priority must be a real number")
    return float(value)


class PriorityQueueAging:
    """Min-priority queue; each ``pop`` decrements every survivor's priority."""

    def __init__(self, age_step: float = 1.0) -> None:
        self._step = _req_priority(age_step)
        if self._step < 0:
            raise ValueError("age_step must be non-negative")
        self._items: List[Tuple[float, int, Any]] = []
        self._seq = 0

    def push(self, priority: object, item: Any) -> None:
        self._items.append((_req_priority(priority), self._seq, item))
        self._seq += 1

    def _age(self) -> None:
        self._items = [(p - self._step, s, it) for p, s, it in self._items]

    def _best(self) -> int:
        return min(range(len(self._items)), key=lambda i: (self._items[i][0], self._items[i][1]))

    def pop(self) -> Any:
        if not self._items:
            raise IndexError("pop from empty queue")
        idx = self._best()
        _, _, item = self._items.pop(idx)
        self._age()
        return item

    def peek(self) -> Any:
        if not self._items:
            raise IndexError("peek from empty queue")
        return self._items[self._best()][2]

    def is_empty(self) -> bool:
        return not self._items

    def __len__(self) -> int:
        return len(self._items)


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
    pq = PriorityQueueAging()
    pq.push(1, "high"); pq.push(5, "low")
    assert pq.pop() == "high"  # low aged 5 -> 4
    assert pq.pop() == "low" and pq.is_empty()
    pq2 = PriorityQueueAging()
    pq2.push(3, "a"); pq2.push(3, "b")
    assert pq2.pop() == "a"  # tie broken FIFO
    pq2.push(2, "c")
    # b aged 3 -> 2, tie with c but b arrived earlier
    assert pq2.pop() == "b"
    assert pq2.pop() == "c"
    try:
        pq2.pop()
    except IndexError:
        pass
    else:
        raise AssertionError("pop on empty must raise IndexError")
    try:
        PriorityQueueAging(-1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative age_step must raise ValueError")
    assert stdlib_only()
    print("queue-36 OK: aging priority queue")


if __name__ == "__main__":
    main()
