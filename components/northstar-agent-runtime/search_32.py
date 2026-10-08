"""SMA* (simplified mock), Simulated.

What this IS: mock memory-bounded A* that drops worst leaves over a cap.

What this IS NOT: mock/simplified simulation; dropping leaves loses optimality.
"""

from __future__ import annotations

import ast
import heapq
from typing import Callable, Dict, List, Optional

#: Module version.
SEARCH_32_VERSION = "search-32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-32.v1"


class SearchError(Exception):
    """Fail-closed."""


def sma_star(graph: Dict[str, List[str]], start: str, goal: str,
             heuristic: Callable[[str], float],
             max_nodes: int = 100) -> Optional[List[str]]:
    """Mock SMA*: path within memory cap, or None."""
    if graph is None or heuristic is None:
        raise SearchError("args required")
    if max_nodes < 1:
        raise SearchError("max_nodes must be >= 1")
    openh = [(heuristic(start), 0, [start])]
    while openh:
        _, g, path = heapq.heappop(openh)
        node = path[-1]
        if node == goal:
            return path
        for nb in graph.get(node, []):
            if nb in path:
                continue
            heapq.heappush(openh, (g + 1 + heuristic(nb), g + 1, path + [nb]))
        while len(openh) > max_nodes:
            worst = max(range(len(openh)), key=lambda i: openh[i][0])
            openh[worst] = openh[-1]
            openh.pop()
            heapq.heapify(openh)
    return None

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
    p = sma_star(g, "a", "d", h)
    assert p[0] == "a" and p[-1] == "d"
    assert sma_star(g, "a", "z", h) is None
    assert stdlib_only()
    print("search-32.v1 OK")


if __name__ == "__main__":
    main()
