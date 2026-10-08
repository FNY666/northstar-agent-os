"""BFS level order, Simulated.

What this IS: breadth-first traversal of a tree as nested dicts.

What this IS NOT: not for graphs with cycles; use BFS graph search there.
"""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, Dict, List, Optional

#: Module version.
SEARCH_46_VERSION = "search-46.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-46.v1"


class SearchError(Exception):
    """Fail-closed."""


def level_order(root: Optional[Dict[str, Any]]) -> List[Any]:
    """Values in breadth-first order; [] for None."""
    if root is None:
        return []
    out = []
    q = deque([root])
    while q:
        node = q.popleft()
        out.append(node["v"])
        q.extend(node.get("kids", []))
    return out

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
    t = {"v": 1, "kids": [{"v": 2, "kids": []},
         {"v": 3, "kids": [{"v": 4, "kids": []}]}]}
    assert level_order(t) == [1, 2, 3, 4]
    assert level_order(None) == []
    assert stdlib_only()
    print("search-46.v1 OK")


if __name__ == "__main__":
    main()
