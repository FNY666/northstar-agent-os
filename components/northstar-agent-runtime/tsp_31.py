"""Or-opt relocation improvement (move a segment to a new position) (TSP-031), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-or-opt.v1"


def tour_cost(tour: list[int], dist: list[list[float]]) -> float:
    if not tour:
        return 0.0
    total = 0.0
    for i in range(len(tour)):
        total += dist[tour[i]][tour[(i + 1) % len(tour)]]
    return total


def or_opt(tour: list[int], dist: list[list[float]], seg_len: int = 2) -> list[int]:
    """Move every contiguous segment of length seg_len to the best position."""
    if len(tour) < 2 or seg_len < 1 or seg_len >= len(tour):
        return list(tour)
    best = list(tour)
    best_cost = tour_cost(best, dist)
    n = len(tour)
    improved = True
    while improved:
        improved = False
        for i in range(n):
            seg = [best[(i + k) % n] for k in range(seg_len)]
            rest = [best[(i + k) % n] for k in range(seg_len, n)]
            # try inserting the segment at every position of the remaining tour
            for pos in range(len(rest) + 1):
                cand = rest[:pos] + seg + rest[pos:]
                c = tour_cost(cand, dist)
                if c < best_cost - 1e-12:
                    best = cand
                    best_cost = c
                    n = len(best)
                    improved = True
                    break
            if improved:
                break
    return best


def main() -> None:
    # symmetric instance where moving a segment clearly helps
    dist = [
        [0, 1, 8, 8, 1],
        [1, 0, 1, 8, 8],
        [8, 1, 0, 1, 8],
        [8, 8, 1, 0, 1],
        [1, 8, 8, 1, 0],
    ]
    bad = [0, 2, 4, 1, 3]
    improved = or_opt(bad, dist, seg_len=1)
    assert sorted(improved) == list(range(5))  # still a valid permutation
    assert tour_cost(improved, dist) <= tour_cost(bad, dist)  # never worse
    # a badly ordered tour actually gets better
    assert tour_cost(improved, dist) < tour_cost(bad, dist)

    # degenerate: empty and single-node tours
    assert or_opt([], [[0]]) == []
    assert or_opt([0], [[0]]) == [0]

    # already-good tour keeps its length and stays valid
    good = [0, 1, 2, 3, 4]
    again = or_opt(good, dist, seg_len=2)
    assert sorted(again) == list(range(5))
    assert tour_cost(again, dist) <= tour_cost(good, dist)

    assert stdlib_only()
    print('tsp-or-opt.v1 OK')


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
