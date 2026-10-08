"""RBFS (simplified mock), Simulated.

What this IS: mock recursive best-first search with f-limit backtracking.

What this IS NOT: mock/simplified simulation; not a production pathfinder.
"""

from __future__ import annotations

import ast
from typing import Callable, Dict, List, Optional

#: Module version.
SEARCH_31_VERSION = "search-31.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-31.v1"


class SearchError(Exception):
    """Fail-closed."""


def rbfs_search(graph: Dict[str, List[str]], start: str, goal: str,
                heuristic: Callable[[str], float],
                max_iters: int = 100000) -> Optional[List[str]]:
    """Mock RBFS: path from start to goal, or None."""
    if graph is None or heuristic is None:
        raise SearchError("args required")
    iters = [0]

    def rec(path: List[str], f_limit: float):
        iters[0] += 1
        if iters[0] > max_iters:
            return None, float("inf")
        node = path[-1]
        if node == goal:
            return path, 0
        succ = []
        for nb in graph.get(node, []):
            if nb in path:
                continue
            succ.append([max(heuristic(nb), heuristic(node)), nb])
        if not succ:
            return None, float("inf")
        succ.sort(key=lambda x: x[0])
        while True:
            best_f, best_nb = succ[0]
            if best_f > f_limit:
                return None, best_f
            alt = succ[1][0] if len(succ) > 1 else float("inf")
            res, bf = rec(path + [best_nb], min(f_limit, alt))
            succ[0][0] = bf
            succ.sort(key=lambda x: x[0])
            if res:
                return res, bf

    res, _ = rec([start], float("inf"))
    return res

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
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    h = {"a": 2, "b": 1, "c": 1, "d": 0}.__getitem__
    p = rbfs_search(g, "a", "d", h)
    assert p[0] == "a" and p[-1] == "d"
    assert rbfs_search(g, "a", "z", h) is None
    assert stdlib_only()
    print("search-31.v1 OK")


if __name__ == "__main__":
    main()
