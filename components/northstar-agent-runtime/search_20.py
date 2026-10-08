"""Bidirectional BFS, Simulated.

What this IS: two-ended BFS meeting in the middle; O(b^(d/2)) time.

What this IS NOT: needs reverse neighbors; plain BFS if unavailable.
"""

from __future__ import annotations

import ast
from collections import deque
from typing import Dict, List, Optional

#: Module version.
SEARCH_20_VERSION = "search-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-20.v1"


class SearchError(Exception):
    """Fail-closed."""


def bidirectional_bfs(graph: Dict[str, List[str]], start: str,
                      goal: str) -> Optional[List[str]]:
    """Path from start to goal via two-ended BFS, or None."""
    if graph is None:
        raise SearchError("graph required")
    if start == goal:
        return [start]
    rev: Dict[str, List[str]] = {}
    for u in graph:
        for v in graph[u]:
            rev.setdefault(v, []).append(u)
    qf, qb = deque([start]), deque([goal])
    pf, pb = {start: [start]}, {goal: [goal]}
    while qf and qb:
        if len(qf) <= len(qb):
            node = qf.popleft()
            for nb in graph.get(node, []):
                if nb in pf:
                    continue
                pf[nb] = pf[node] + [nb]
                if nb in pb:
                    return pf[nb] + pb[nb][-2::-1]
                qf.append(nb)
        else:
            node = qb.popleft()
            for nb in rev.get(node, []):
                if nb in pb:
                    continue
                pb[nb] = pb[node] + [nb]
                if nb in pf:
                    return pf[nb] + pb[nb][-2::-1]
                qb.append(nb)
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
    chain = {"a": ["b"], "b": ["a", "c"], "c": ["b", "d"],
             "d": ["c", "e"], "e": ["d"]}
    assert bidirectional_bfs(chain, "a", "e") == ["a", "b", "c", "d", "e"]
    assert bidirectional_bfs(chain, "a", "z") is None
    assert stdlib_only()
    print("search-20.v1 OK")


if __name__ == "__main__":
    main()
