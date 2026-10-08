"""Map coloring (mock constraint), Simulated.

What this IS: mock backtracking with forward checking for graph coloring.

What this IS NOT: mock/simplified simulation; not a full CSP solver.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional

#: Module version.
SEARCH_45_VERSION = "search-45.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-45.v1"


class SearchError(Exception):
    """Fail-closed."""


def map_coloring(adj: Dict[str, List[str]],
                 colors: List[str]) -> Optional[Dict[str, str]]:
    """Mock CSP: valid coloring, or None if unsatisfiable."""
    if adj is None or colors is None:
        raise SearchError("args required")
    nodes = list(adj)
    assignment: Dict[str, str] = {}
    domains = {n: set(colors) for n in nodes}

    def select() -> Optional[str]:
        un = [n for n in nodes if n not in assignment]
        return min(un, key=lambda n: len(domains[n])) if un else None

    def bt() -> Optional[Dict[str, str]]:
        n = select()
        if n is None:
            return dict(assignment)
        for c in sorted(domains[n]):
            if any(assignment.get(nb) == c for nb in adj[n]):
                continue
            assignment[n] = c
            removed = []
            ok = True
            for nb in adj[n]:
                if nb not in assignment and c in domains[nb]:
                    domains[nb].discard(c)
                    removed.append(nb)
                    if not domains[nb]:
                        ok = False
                        break
            if ok:
                r = bt()
                if r is not None:
                    return r
            del assignment[n]
            for nb in removed:
                domains[nb].add(c)
        return None

    return bt()

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
    tri = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}
    r = map_coloring(tri, ["R", "G", "B"])
    assert r is not None and len(r) == 3
    assert map_coloring(tri, ["R", "G"]) is None
    assert stdlib_only()
    print("search-45.v1 OK")


if __name__ == "__main__":
    main()
