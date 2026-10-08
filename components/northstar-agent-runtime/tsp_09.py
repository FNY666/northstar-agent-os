"""3-opt single-pass local search for TSP tours (TSP-009), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-3opt.v1"


def tour_length(dist, tour):
    if len(tour) <= 1:
        return 0.0
    return sum(dist[tour[i]][tour[(i + 1) % len(tour)]] for i in range(len(tour)))


def three_opt_candidates(tour, i, j, k):
    # break edges (t[i],t[i+1]), (t[j],t[j+1]), (t[k],t[k+1]); segments:
    s1 = tour[:i + 1]
    s2 = tour[i + 1:j + 1]
    s3 = tour[j + 1:k + 1]
    s4 = tour[k + 1:]
    cands = []
    for mid in ([s2, s3], [s3, s2]):
        for r2 in (False, True):
            for r3 in (False, True):
                a, b = mid
                if r2:
                    a = a[::-1]
                if r3:
                    b = b[::-1]
                cands.append(s1 + a + b + s4)
    return cands


def improve_3opt_single_pass(dist, tour):
    """One pass over all triples (i, j, k): apply an improving 3-opt move
    when found, then continue scanning (no restart)."""
    n = len(tour)
    if n <= 3:
        return list(tour), tour_length(dist, tour)
    cur = list(tour)
    cur_len = tour_length(dist, cur)
    for i in range(n):
        for j in range(i + 1, n):
            for k in range(j + 1, n):
                for cand in three_opt_candidates(cur, i, j, k):
                    cand_len = tour_length(dist, cand)
                    if cand_len < cur_len - 1e-9:
                        cur, cur_len = cand, cand_len
    return cur, cur_len


def main() -> None:
    dist = [
        [0, 10, 15, 20],
        [10, 0, 35, 25],
        [15, 35, 0, 30],
        [20, 25, 30, 0],
    ]
    # worst tour for this instance: 0-2-1-3-0 = 95
    start = [0, 2, 1, 3]
    before = tour_length(dist, start)
    tour, length = improve_3opt_single_pass(dist, start)
    assert sorted(tour) == [0, 1, 2, 3]
    assert length == 80  # single pass reaches the known optimum here
    assert length == tour_length(dist, tour)
    assert length <= before  # never worsens the tour
    assert improve_3opt_single_pass(dist, [0]) == ([0], 0.0)
    assert improve_3opt_single_pass(dist, []) == ([], 0.0)
    # non-worsening property on a 6-city instance
    d6 = [
        [0, 2, 9, 10, 7, 3],
        [2, 0, 6, 4, 8, 5],
        [9, 6, 0, 8, 3, 7],
        [10, 4, 8, 0, 5, 6],
        [7, 8, 3, 5, 0, 4],
        [3, 5, 7, 6, 4, 0],
    ]
    t6, l6 = improve_3opt_single_pass(d6, [0, 1, 2, 3, 4, 5])
    assert sorted(t6) == [0, 1, 2, 3, 4, 5]
    assert l6 <= tour_length(d6, [0, 1, 2, 3, 4, 5])
    assert l6 == tour_length(d6, t6)
    assert stdlib_only()
    print('tsp-3opt.v1 OK')


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
