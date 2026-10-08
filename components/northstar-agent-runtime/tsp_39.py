"""Tour splitting into subtours with capacity (mock) (TSP-039), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-tour-split.v1"


def split_tour(tour: list[int], capacity: int) -> list[list[int]]:
    """Split a tour into contiguous subtours, each with at most `capacity` nodes."""
    if not tour:
        return []
    if capacity <= 0:
        raise ValueError("capacity must be positive")
    return [tour[i:i + capacity] for i in range(0, len(tour), capacity)]


def split_with_demand(tour: list[int], demand: dict[int, int], capacity: int) -> list[list[int]]:
    """Split a tour so the total demand of each subtour does not exceed capacity
    (mock: greedy, cut before the subtour would overflow)."""
    if not tour:
        return []
    if capacity <= 0:
        raise ValueError("capacity must be positive")
    subs: list[list[int]] = []
    cur: list[int] = []
    cur_load = 0
    for v in tour:
        d = demand.get(v, 0)
        if cur and cur_load + d > capacity:
            subs.append(cur)
            cur, cur_load = [], 0
        cur.append(v)
        cur_load += d
    if cur:
        subs.append(cur)
    return subs


def main() -> None:
    tour = [0, 1, 2, 3, 4, 5]
    subs = split_tour(tour, 2)
    assert subs == [[0, 1], [2, 3], [4, 5]]  # exact capacity cuts
    assert [v for s in subs for v in s] == tour  # lossless: every city appears once
    assert all(len(s) <= 2 for s in subs)  # capacity respected

    # degenerate cases
    assert split_tour([], 3) == []
    assert split_tour([0], 3) == [[0]]
    assert split_tour([0, 1, 2], 10) == [[0, 1, 2]]  # capacity > n -> one subtour

    # capacity of 1 -> singleton subtours
    assert split_tour(tour, 1) == [[0], [1], [2], [3], [4], [5]]

    # demand-based splitting: demands 1 each, capacity 2 -> pairs
    demand = {i: 1 for i in range(6)}
    dsubs = split_with_demand(tour, demand, 2)
    assert dsubs == [[0, 1], [2, 3], [4, 5]]
    assert all(sum(demand[v] for v in s) <= 2 for s in dsubs)
    assert split_with_demand([], demand, 2) == []

    # uneven demands {2,2,1,1} with capacity 3: greedy cuts -> [[0],[1,2],[3]]
    d2 = {0: 2, 1: 2, 2: 1, 3: 1}
    ud = split_with_demand([0, 1, 2, 3], d2, 3)
    assert ud == [[0], [1, 2], [3]]
    assert all(sum(d2[v] for v in s) <= 3 for s in ud)  # capacity respected
    assert [v for s in ud for v in s] == [0, 1, 2, 3]  # lossless

    assert stdlib_only()
    print('tsp-tour-split.v1 OK')


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
