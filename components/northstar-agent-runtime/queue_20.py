"""round_robin: round-robin CPU scheduling: completion order for tasks under a time quantum. IS: a completion-order list; non-positive quantum or durations raise ValueError. IS NOT: a preemptive priority scheduler or I/O-aware simulation."""

from __future__ import annotations

import ast
from collections import deque
from typing import List, Tuple
VERSION = "queue-20.v1"

def _req_tasks(tasks: object) -> List[Tuple[str, int]]:
    if not isinstance(tasks, list) or not tasks:
        raise ValueError("tasks must be a non-empty list of (name, duration)")
    clean = []
    for t in tasks:
        if not isinstance(t, tuple) or len(t) != 2:
            raise ValueError("each task must be a (name, duration) tuple")
        name, dur = t
        if not isinstance(name, str):
            raise ValueError("task name must be a string")
        if isinstance(dur, bool) or not isinstance(dur, int) or dur <= 0:
            raise ValueError("task duration must be a positive int")
        clean.append((name, dur))
    return clean


def round_robin(tasks: List[Tuple[str, int]], quantum: int) -> List[str]:
    """Return task names in the order they finish under round-robin."""
    tasks = _req_tasks(tasks)
    if isinstance(quantum, bool) or not isinstance(quantum, int) or quantum <= 0:
        raise ValueError("quantum must be a positive int")
    q: deque = deque([[name, dur] for name, dur in tasks])
    done: List[str] = []
    while q:
        name, remaining = q.popleft()
        remaining -= quantum
        if remaining <= 0:
            done.append(name)
        else:
            q.append([name, remaining])
    return done


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
    assert round_robin([("a", 3), ("b", 2)], 2) == ["b", "a"]
    assert round_robin([("a", 2), ("b", 2)], 2) == ["a", "b"]
    assert round_robin([("x", 5)], 10) == ["x"]
    assert round_robin([("a", 4), ("b", 4), ("c", 4)], 2) == ["a", "b", "c"]
    try:
        round_robin([("a", 3)], 0)
    except ValueError:
        pass
    else:
        raise AssertionError("quantum 0 must raise ValueError")
    try:
        round_robin([("a", 0)], 2)
    except ValueError:
        pass
    else:
        raise AssertionError("zero duration must raise ValueError")
    try:
        round_robin([], 2)
    except ValueError:
        pass
    else:
        raise AssertionError("empty tasks must raise ValueError")
    assert stdlib_only()
    print("queue-20 OK: round-robin scheduler")


if __name__ == "__main__":
    main()
