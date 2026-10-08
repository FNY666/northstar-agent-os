"""Multi-objective TSP (mock: pareto front of length vs max-edge) (TSP-044), Simulated."""
from __future__ import annotations
import ast
import itertools

VERSION = "tsp-multi-objective.v1"

def objectives(tour: list[int], dist: list[list[float]]) -> tuple[float, float]:
    if len(tour) < 2:
        return (0.0, 0.0)
    edges = [dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour))]
    return (sum(edges), max(edges))

def dominates(a: tuple[float, float], b: tuple[float, float]) -> bool:
    return (a[0] <= b[0] and a[1] <= b[1]) and (a[0] < b[0] or a[1] < b[1])

def pareto_front(dist: list[list[float]]) -> list[tuple[list[int], tuple[float, float]]]:
    """Pareto front over all permutations (tiny n only)."""
    n = len(dist)
    if n == 0:
        return []
    cands = []
    for perm in itertools.permutations(range(n)):
        if perm[0] != 0:
            continue  # fix rotation symmetry
        tour = list(perm)
        cands.append((tour, objectives(tour, dist)))
    front = []
    for tour, obj in cands:
        if not any(dominates(other_obj, obj) for _, other_obj in cands):
            front.append((tour, obj))
    return front

def main() -> None:
    d = [
        [0, 1, 4, 3],
        [1, 0, 2, 5],
        [4, 2, 0, 1],
        [3, 5, 1, 0],
    ]
    front = pareto_front(d)
    assert len(front) >= 1
    for tour, obj in front:
        assert sorted(tour) == [0, 1, 2, 3]
        assert obj == objectives(tour, d)
    # no front member dominated by another
    for i, (_, o1) in enumerate(front):
        for j, (_, o2) in enumerate(front):
            if i != j:
                assert not dominates(o1, o2)
    assert pareto_front([]) == []
    f1 = pareto_front([[0]])
    assert len(f1) == 1 and f1[0][1] == (0.0, 0.0)
    assert stdlib_only()
    print('tsp-multi-objective.v1 OK')

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses", "random"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True

if __name__ == "__main__":
    main()
