"""Tour length calculator and tour validity checker (TSP-019), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-tour-utils.v1"


def is_valid_tour(tour: list[int], n: int) -> bool:
    """A tour is valid if it is a permutation of 0..n-1 (each city exactly once)."""
    if n == 0:
        return tour == []
    if n == 1:
        return tour == [0]
    return sorted(tour) == list(range(n))


def tour_length(dist: list[list[float]], tour: list[int]) -> float:
    """Total tour length, implicitly returning to the start city."""
    n = len(tour)
    if n == 0:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % n]] for i in range(n))


def tour_length_checked(dist: list[list[float]], tour: list[int]) -> float:
    """Like tour_length, but raises ValueError on an invalid tour."""
    if not is_valid_tour(tour, len(dist)):
        raise ValueError(f"invalid tour {tour} for n={len(dist)}")
    return tour_length(dist, tour)


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    tour = [0, 1, 3, 2]
    assert is_valid_tour(tour, 4)
    assert tour_length_checked(dist, tour) == 80.0, "0-1-3-2-0 = 10+25+30+15 = 80"
    assert is_valid_tour([], 0)
    assert tour_length([], []) == 0.0
    assert is_valid_tour([0], 1)
    assert tour_length([[0]], [0]) == 0.0
    assert tour_length(dist, tour) == sum(
        dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour))
    )
    for bad in ([0, 1, 2], [0, 1, 2, 2], [0, 1, 2, 5], [-1, 0, 1, 2]):
        assert not is_valid_tour(bad, 4), f"{bad} must be invalid"
        try:
            tour_length_checked(dist, bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{bad} must raise ValueError")
    assert stdlib_only()
    print("tsp-tour-utils.v1 OK")


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
