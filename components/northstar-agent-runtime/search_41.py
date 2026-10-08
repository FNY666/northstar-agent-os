"""Alpha-beta pruning (mock), Simulated.

What this IS: mock minimax with alpha-beta cutoffs; counts leaf evals.

What this IS NOT: mock/simplified simulation; needs good move ordering to prune.
"""

from __future__ import annotations

import ast
from typing import Any, Callable, List, Optional

#: Module version.
SEARCH_41_VERSION = "search-41.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-41.v1"


class SearchError(Exception):
    """Fail-closed."""


def alpha_beta(node: Any, depth: int, alpha: float, beta: float,
               maximizing: bool, children_fn: Callable[[Any], List[Any]],
               value_fn: Callable[[Any], float],
               counter: Optional[List[int]] = None) -> float:
    """Mock alpha-beta value; counter[0] counts leaf evaluations."""
    if children_fn is None or value_fn is None:
        raise SearchError("args required")
    kids = children_fn(node)
    if depth == 0 or not kids:
        if counter is not None:
            counter[0] += 1
        return value_fn(node)
    if maximizing:
        v = float("-inf")
        for c in kids:
            v = max(v, alpha_beta(c, depth - 1, alpha, beta, False,
                                 children_fn, value_fn, counter))
            alpha = max(alpha, v)
            if beta <= alpha:
                break
        return v
    v = float("inf")
    for c in kids:
        v = min(v, alpha_beta(c, depth - 1, alpha, beta, True,
                             children_fn, value_fn, counter))
        beta = min(beta, v)
        if beta <= alpha:
            break
    return v

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
    kids = {"r": ["a", "b"], "a": ["a1", "a2"], "b": ["b1", "b2"]}
    vals = {"a1": 3, "a2": 5, "b1": 2, "b2": 9}
    c = [0]
    v = alpha_beta("r", 2, float("-inf"), float("inf"), True,
                   kids.get, vals.__getitem__, c)
    assert v == 3 and c[0] == 3
    assert stdlib_only()
    print("search-41.v1 OK")


if __name__ == "__main__":
    main()
