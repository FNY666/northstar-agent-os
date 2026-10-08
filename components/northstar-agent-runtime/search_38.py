"""Tabu search (mock), Simulated.

What this IS: mock local search with a tabu list to escape local optima.

What this IS NOT: mock/simplified simulation; tabu tenure is fixed.
"""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, Callable, Iterable

#: Module version.
SEARCH_38_VERSION = "search-38.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-38.v1"


class SearchError(Exception):
    """Fail-closed."""


def tabu_search(f: Callable[[Any], float], start: Any,
                neighbors: Callable[[Any], Iterable[Any]],
                iters: int = 100, tabu_size: int = 10) -> Any:
    """Mock tabu search: best state seen (never revisits tabu states)."""
    if f is None or neighbors is None:
        raise SearchError("args required")
    tabu = deque(maxlen=tabu_size)
    cur = start
    best, best_v = cur, f(cur)
    for _ in range(iters):
        cands = [n for n in neighbors(cur) if n not in tabu]
        if not cands:
            break
        nxt = max(cands, key=f)
        tabu.append(cur)
        cur = nxt
        if f(cur) > best_v:
            best, best_v = cur, f(cur)
    return best

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "collections", "dataclasses", "heapq",
               "itertools", "math", "pathlib", "random", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    f = lambda x: -(x - 5) ** 2
    nb = lambda x: [n for n in (x - 1, x + 1) if 0 <= n <= 10]
    assert tabu_search(f, 0, nb) == 5
    assert tabu_search(f, 10, nb) == 5
    assert stdlib_only()
    print("search-38.v1 OK")


if __name__ == "__main__":
    main()
