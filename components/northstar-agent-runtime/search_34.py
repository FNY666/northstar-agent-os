"""Hill climbing, Simulated.

What this IS: greedy local optimization; climbs to a local optimum.

What this IS NOT: not global; stuck on plateaus and local maxima.
"""

from __future__ import annotations

import ast
from typing import Any, Callable, Iterable

#: Module version.
SEARCH_34_VERSION = "search-34.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-34.v1"


class SearchError(Exception):
    """Fail-closed."""


def hill_climbing(f: Callable[[Any], float], start: Any,
                  neighbors: Callable[[Any], Iterable[Any]],
                  max_iters: int = 1000) -> Any:
    """Local optimum reachable from start via steepest ascent."""
    if f is None or neighbors is None:
        raise SearchError("args required")
    cur, cur_v = start, f(start)
    for _ in range(max_iters):
        best_n, best_v = None, cur_v
        for n in neighbors(cur):
            v = f(n)
            if v > best_v:
                best_n, best_v = n, v
        if best_n is None:
            break
        cur, cur_v = best_n, best_v
    return cur

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
    assert hill_climbing(f, 0, nb) == 5
    assert hill_climbing(f, 10, nb) == 5
    assert stdlib_only()
    print("search-34.v1 OK")


if __name__ == "__main__":
    main()
