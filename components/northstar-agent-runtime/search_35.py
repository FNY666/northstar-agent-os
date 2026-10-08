"""Random-restart hill climbing, Simulated.

What this IS: hill climbing from several starts; keeps the best optimum.

What this IS NOT: still no global guarantee; seeded for determinism.
"""

from __future__ import annotations

import ast
import random
from typing import Any, Callable, Iterable, List

#: Module version.
SEARCH_35_VERSION = "search-35.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-35.v1"


class SearchError(Exception):
    """Fail-closed."""


def random_restart_hill_climbing(f: Callable[[Any], float], starts: List[Any],
                                 neighbors: Callable[[Any], Iterable[Any]],
                                 max_iters: int = 1000, seed: int = 0) -> Any:
    """Best local optimum over shuffled restarts (deterministic by seed)."""
    if f is None or neighbors is None:
        raise SearchError("args required")
    rng = random.Random(seed)
    order = list(starts)
    rng.shuffle(order)
    best, best_v = None, None
    for s in order:
        cur, cur_v = s, f(s)
        for _ in range(max_iters):
            bn, bv = None, cur_v
            for n in neighbors(cur):
                v = f(n)
                if v > bv:
                    bn, bv = n, v
            if bn is None:
                break
            cur, cur_v = bn, bv
        if best_v is None or cur_v > best_v:
            best, best_v = cur, cur_v
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
    f = lambda x: max(3 - abs(x - 2), 5 - abs(x - 8))
    nb = lambda x: [n for n in (x - 1, x + 1) if 0 <= n <= 10]
    assert random_restart_hill_climbing(f, [0, 9], nb) == 8
    assert random_restart_hill_climbing(f, [0], nb) == 2
    assert stdlib_only()
    print("search-35.v1 OK")


if __name__ == "__main__":
    main()
