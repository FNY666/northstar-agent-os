"""Genetic search (mock), Simulated.

What this IS: mock population optimizer: selection, crossover, mutation.

What this IS NOT: mock/simplified simulation; no optimality guarantee.
"""

from __future__ import annotations

import ast
import random
from typing import Any, Callable, List

#: Module version.
SEARCH_37_VERSION = "search-37.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-37.v1"


class SearchError(Exception):
    """Fail-closed."""


def genetic_search(fitness: Callable[[List[Any]], float], gene_pool: List[Any],
                   gene_len: int, pop_size: int = 20, generations: int = 50,
                   seed: int = 0) -> List[Any]:
    """Mock GA: best individual after fixed generations (seeded)."""
    if fitness is None:
        raise SearchError("fitness required")
    if gene_len < 1 or pop_size < 1:
        raise SearchError("gene_len and pop_size must be >= 1")
    rng = random.Random(seed)
    pop = [[rng.choice(gene_pool) for _ in range(gene_len)] for _ in range(pop_size)]
    best = max(pop, key=fitness)
    for _ in range(generations):
        scored = sorted(pop, key=fitness, reverse=True)
        elites = scored[:max(1, pop_size // 4)]
        children = []
        while len(children) < pop_size - len(elites):
            p1, p2 = rng.choice(elites), rng.choice(elites)
            cut = rng.randrange(gene_len) if gene_len > 1 else 0
            child = p1[:cut] + p2[cut:]
            child = [rng.choice(gene_pool) if rng.random() < 0.1 else g
                     for g in child]
            children.append(child)
        pop = elites + children
        cand = max(pop, key=fitness)
        if fitness(cand) > fitness(best):
            best = cand
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
    fit = sum
    best = genetic_search(fit, [0, 1], 5, pop_size=20, generations=50, seed=0)
    assert fit(best) == 5 and len(best) == 5
    assert stdlib_only()
    print("search-37.v1 OK")


if __name__ == "__main__":
    main()
