"""PrintSpooler: FIFO print-job spooler tracking submission order and page totals. IS: a FIFO spooler; process() drains in order; jobs with bad pages raise ValueError. IS NOT: a priority print queue or a duplex-aware scheduler."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, List, Tuple
VERSION = "queue-21.v1"

def _req_job(name: object, pages: object) -> Tuple[str, int]:
    if not isinstance(name, str) or not name:
        raise ValueError("job name must be a non-empty string")
    if isinstance(pages, bool) or not isinstance(pages, int) or pages <= 0:
        raise ValueError("pages must be a positive int")
    return (name, pages)


class PrintSpooler:
    """First-in-first-out print spooler."""

    def __init__(self) -> None:
        self._q: deque = deque()

    def spool(self, name: str, pages: int) -> None:
        self._q.append(_req_job(name, pages))

    def process(self) -> List[str]:
        """Drain the spooler, returning job names in print order."""
        out = []
        while self._q:
            out.append(self._q.popleft()[0])
        return out

    def pending(self) -> int:
        return len(self._q)

    def total_pages(self) -> int:
        return sum(pages for _, pages in self._q)


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
    sp = PrintSpooler()
    assert sp.pending() == 0 and sp.process() == []
    sp.spool("a", 3); sp.spool("b", 2); sp.spool("c", 5)
    assert sp.pending() == 3 and sp.total_pages() == 10
    assert sp.process() == ["a", "b", "c"]
    assert sp.pending() == 0 and sp.total_pages() == 0
    for name, pages in [("", 3), ("x", 0), ("x", -1), ("x", "3"), (123, 3)]:
        try:
            sp.spool(name, pages)
        except ValueError:
            pass
        else:
            raise AssertionError(f"spool({name!r}, {pages!r}) must raise ValueError")
    assert stdlib_only()
    print("queue-21 OK: FIFO print spooler")


if __name__ == "__main__":
    main()
