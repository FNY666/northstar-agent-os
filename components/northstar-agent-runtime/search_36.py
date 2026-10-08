"""Simulated annealing (mock), Simulated.

What this IS: mock probabilistic optimizer with cooling schedule; seeded.

What this IS NOT: mock/simplified simulation; no convergence guarantee.
"""

from __future__ import annotations

import ast
import math
import random
from typing import Any, Callable, Iterable

#: Module version.
SEARCH_36_VERSION = "search-36.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-36.v1"


class SearchError(Exception):
    """Fail-closed."""


def simulated_annealing(f: Callable[[Any], float], start: Any,
                        neighbors: Callable[[Any], Iterable[Any]],
                        iters: int = 1000, t0: float = 10.0,
                        cooling: float = 0.995, seed: int = 0) -> Any:
    """Mock SA: best state seen during the anneal (deterministic by seed)."""
    if f is None or neighbors is None:
        raise SearchError("args required")
    rng = random.Random(seed)
    cur, cur_v = start, f(start)
    best, best_v = cur, cur_v
    t = t0
    for _ in range(iters):
        nbs = list(neighbors(cur))
        if not nbs:
            break
        nxt = rng.choice(nbs)
        nv = f(nxt)
        if nv > cur_v or rng.random() < math.exp((nv - cur_v) / max(t, 1e-9)):
            cur, cur_v = nxt, nv
            if nv > best_v:
                best, best_v = nxt, nv
        t *= cooling
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
    assert simulated_annealing(f, 0, nb, seed=1) == 5
    assert stdlib_only()
    print("search-36.v1 OK")


if __name__ == "__main__":
    main()
