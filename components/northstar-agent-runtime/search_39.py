"""MCTS (mock), Simulated.

What this IS: mock Monte Carlo tree search with UCB1 over flat actions.

What this IS NOT: mock/simplified simulation; no real tree expansion.
"""

from __future__ import annotations

import ast
import math
import random
from typing import Any, Callable, List

#: Module version.
SEARCH_39_VERSION = "search-39.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-39.v1"


class SearchError(Exception):
    """Fail-closed."""


def mcts_search(actions: Callable[[], List[Any]],
                rollout: Callable[[Any], float],
                iters: int = 100, seed: int = 0) -> Any:
    """Mock MCTS: action with best mean rollout reward (seeded)."""
    if actions is None or rollout is None:
        raise SearchError("args required")
    rng = random.Random(seed)
    acts = list(actions())
    if not acts:
        raise SearchError("no actions")
    wins = {a: 0.0 for a in acts}
    visits = {a: 0 for a in acts}
    total = 0
    for _ in range(iters):
        total += 1

        def ucb(a: Any) -> float:
            if visits[a] == 0:
                return float("inf")
            return wins[a] / visits[a] + math.sqrt(2 * math.log(total) / visits[a])

        a = max(acts, key=ucb)
        r = rollout(a) + rng.random() * 1e-9
        visits[a] += 1
        wins[a] += r
    return max(acts, key=lambda a: wins[a] / visits[a] if visits[a] else 0)

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
    acts = lambda: ["a", "b"]
    roll = {"a": 1.0, "b": 0.0}.__getitem__
    assert mcts_search(acts, roll, iters=50, seed=0) == "a"
    assert stdlib_only()
    print("search-39.v1 OK")


if __name__ == "__main__":
    main()
