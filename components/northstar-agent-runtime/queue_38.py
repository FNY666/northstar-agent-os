"""DelayQueue: delay queue: items become available at their timestamp; pop_ready drains due items. IS: due items in (available_at, insertion) order; bad timestamps raise ValueError. IS NOT: a real-time timer wheel or a blocking take()."""

from __future__ import annotations

import ast
from typing import Any, List, Tuple
VERSION = "queue-38.v1"

def _req_ts(ts: object) -> float:
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or ts < 0:
        raise ValueError("available_at must be a non-negative number")
    return float(ts)


class DelayQueue:
    """Items are retrievable once ``now >= available_at``."""

    def __init__(self) -> None:
        self._items: List[Tuple[float, int, Any]] = []
        self._seq = 0

    def push(self, available_at: float, item: Any) -> None:
        self._items.append((_req_ts(available_at), self._seq, item))
        self._seq += 1

    def pop_ready(self, now: float) -> List[Any]:
        """Remove and return all items with ``available_at <= now``, in due order."""
        now = _req_ts(now)
        due = sorted([e for e in self._items if e[0] <= now])
        due_set = set(map(id, due))
        self._items = [e for e in self._items if id(e) not in due_set]
        return [item for _, _, item in due]

    def pending(self) -> int:
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
    dq = DelayQueue()
    dq.push(10.0, "a"); dq.push(5.0, "b"); dq.push(7.0, "c")
    assert dq.pending() == 3
    assert dq.pop_ready(6.0) == ["b"]
    assert dq.pop_ready(4.0) == []
    assert dq.pop_ready(10.0) == ["c", "a"]
    assert dq.pending() == 0
    dq.push(3.0, "x"); dq.push(3.0, "y")
    assert dq.pop_ready(3.0) == ["x", "y"]  # insertion order on ties
    try:
        dq.push(-1.0, "z")
    except ValueError:
        pass
    else:
        raise AssertionError("negative timestamp must raise ValueError")
    assert stdlib_only()
    print("queue-38 OK: delay queue")


if __name__ == "__main__":
    main()
