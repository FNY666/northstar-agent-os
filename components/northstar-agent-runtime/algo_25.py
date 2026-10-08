"""Floyd-Warshall all-pairs shortest paths.

Dynamic programming over intermediate vertices k: for every pair (i, j),
d[i][j] = min(d[i][j], d[i][k] + d[k][j]). Handles negative edge weights
(no negative cycles); unreachable pairs stay float("inf").

Time complexity: O(V^3). Space: O(V^2).
"""

from typing import Dict, List, Tuple

ALGO_25_VERSION = "algo-25.v1"

_STDLIB_USED = {"typing", "ast", "pathlib"}

_INF = float("inf")


def floyd_warshall(nodes: List, edges: List[Tuple]) -> Dict:
    """Return dict-of-dicts distance matrix for directed edges (u, v, w).

    Parallel edges keep the minimum weight. Self distance is 0; unreachable
    pairs are float("inf").
    """
    dist = {u: {v: (0 if u == v else _INF) for v in nodes} for u in nodes}
    for u, v, w in edges:
        if w < dist[u][v]:
            dist[u][v] = w
    for k in nodes:
        dk = dist[k]
        for i in nodes:
            dik = dist[i][k]
            if dik == _INF:
                continue
            di = dist[i]
            for j in nodes:
                nd = dik + dk[j]
                if nd < di[j]:
                    di[j] = nd
    return dist


def stdlib_only() -> bool:
    """Assert every imported top-level module is one actually used from the stdlib."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= _STDLIB_USED, f"non-stdlib/unused import: {imported - _STDLIB_USED}"
    return True


def main() -> None:
    nodes = [0, 1, 2, 3]
    edges = [(0, 1, 4), (0, 2, 1), (2, 1, 2), (1, 3, 1), (2, 3, 5)]
    d = floyd_warshall(nodes, edges)
    assert d[0][0] == 0 and d[0][1] == 3 and d[0][2] == 1 and d[0][3] == 4, d[0]
    assert d[2][3] == 3 and d[1][3] == 1 and d[3][0] == float("inf")
    d2 = floyd_warshall([], [])
    assert d2 == {}
    d3 = floyd_warshall(["A"], [])
    assert d3 == {"A": {"A": 0}}
    d4 = floyd_warshall(["A", "B"], [("A", "B", 9), ("A", "B", 2)])
    assert d4["A"]["B"] == 2  # parallel edges: keep minimum
    d5 = floyd_warshall(["A", "B", "C"], [("A", "B", -1), ("B", "C", -2)])
    assert d5["A"]["C"] == -3  # negative weights ok
    assert stdlib_only() is True
    print("algo_25 OK")


if __name__ == "__main__":
    main()
