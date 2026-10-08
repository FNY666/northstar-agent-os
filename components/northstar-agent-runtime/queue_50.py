"""EventLoop: tiny event loop: schedule callbacks with delays, tick time forward, run to completion. IS: a deterministic timer queue; negative delays raise ValueError. IS NOT: a real async reactor with I/O (this is a simulated clock)."""

from __future__ import annotations

import ast
from typing import Any, List, Tuple
VERSION = "queue-50.v1"

def _req_delay(delay: object) -> float:
    if isinstance(delay, bool) or not isinstance(delay, (int, float)) or delay < 0:
        raise ValueError("delay must be a non-negative number")
    return float(delay)


class EventLoop:
    """Simulated-time event loop backed by a timer list."""

    def __init__(self) -> None:
        self._now = 0.0
        self._seq = 0
        self._pending: List[Tuple[float, int, Any]] = []
        self._fired: List[Any] = []

    def schedule(self, delay: float, name: Any) -> None:
        """Schedule ``name`` to fire ``delay`` seconds from now."""
        if not isinstance(name, str) or not name:
            raise ValueError("name must be a non-empty string")
        self._pending.append((_req_delay(delay) + self._now, self._seq, name))
        self._seq += 1

    def tick(self, dt: float) -> List[Any]:
        """Advance the clock by ``dt`` and return newly fired names in order."""
        dt = _req_delay(dt)
        self._now += dt
        due = sorted(e for e in self._pending if e[0] <= self._now)
        due_ids = {id(e) for e in due}
        self._pending = [e for e in self._pending if id(e) not in due_ids]
        names = [name for _, _, name in due]
        self._fired.extend(names)
        return names

    def run(self) -> List[Any]:
        """Fire every scheduled event in (time, insertion) order."""
        names = [name for _, _, name in sorted(self._pending)]
        self._pending = []
        self._fired.extend(names)
        return names

    @property
    def now(self) -> float:
        return self._now

    def pending(self) -> int:
        return len(self._pending)


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
    loop = EventLoop()
    loop.schedule(5, "a"); loop.schedule(1, "b"); loop.schedule(3, "c")
    assert loop.pending() == 3
    assert loop.tick(2) == ["b"] and loop.now == 2.0
    assert loop.tick(2) == ["c"] and loop.pending() == 1
    loop.schedule(0, "d")
    assert loop.tick(0) == ["d"]
    assert loop.run() == ["a"] and loop.pending() == 0
    loop2 = EventLoop()
    loop2.schedule(2, "x"); loop2.schedule(2, "y")
    assert loop2.run() == ["x", "y"]  # insertion order on ties
    try:
        loop2.schedule(-1, "z")
    except ValueError:
        pass
    else:
        raise AssertionError("negative delay must raise ValueError")
    try:
        loop2.schedule(1, "")
    except ValueError:
        pass
    else:
        raise AssertionError("empty name must raise ValueError")
    assert stdlib_only()
    print("queue-50 OK: simulated event loop")


if __name__ == "__main__":
    main()
