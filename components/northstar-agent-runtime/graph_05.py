"""graph_05: Floyd-Warshall all-pairs shortest paths. Standard library only.

GRAPH_05_VERSION = graph-05.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Optional, Tuple

GRAPH_05_VERSION = "graph-05.v1"


def floyd_warshall(
    nodes: List[Hashable], edges: List[Tuple[Hashable, Hashable, float]]
) -> Tuple[Dict[Hashable, Dict[Hashable, float]], Dict[Hashable, Dict[Hashable, Optional[Hashable]]]]:
    """Returns (dist, nxt) matrices. nxt[u][v] = next hop from u toward v."""
    INF = float("inf")
    dist: Dict[Hashable, Dict[Hashable, float]] = {
        u: {v: (0.0 if u == v else INF) for v in nodes} for u in nodes
    }
    nxt: Dict[Hashable, Dict[Hashable, Optional[Hashable]]] = {
        u: {v: None for v in nodes} for u in nodes
    }
    for u, v, w in edges:
        if w < dist[u][v]:
            dist[u][v] = w
            nxt[u][v] = v
    for k in nodes:
        dk = dist[k]
        for i in nodes:
            dik = dist[i][k]
            if dik == INF:
                continue
            di = dist[i]
            ni = nxt[i]
            for j in nodes:
                nd = dik + dk[j]
                if nd < di[j]:
                    di[j] = nd
                    ni[j] = ni[k]
    return dist, nxt


def reconstruct_path(
    nxt: Dict[Hashable, Dict[Hashable, Optional[Hashable]]], u: Hashable, v: Hashable
) -> Optional[List[Hashable]]:
    """Reconstruct path u -> v using nxt matrix, or None."""
    if nxt[u][v] is None:
        return [u] if u == v else None
    path = [u]
    while u != v:
        nxt_hop = nxt[u][v]
        assert nxt_hop is not None
        u = nxt_hop
        path.append(u)
    return path


def test_floyd_warshall_basic():
    nodes = ["a", "b", "c"]
    edges = [("a", "b", 1), ("b", "c", 2), ("a", "c", 10)]
    dist, _ = floyd_warshall(nodes, edges)
    assert dist["a"]["c"] == 3.0
    assert dist["a"]["a"] == 0.0
    assert dist["c"]["a"] == float("inf")


def test_floyd_warshall_path():
    nodes = ["a", "b", "c"]
    edges = [("a", "b", 1), ("b", "c", 2), ("a", "c", 10)]
    _, nxt = floyd_warshall(nodes, edges)
    assert reconstruct_path(nxt, "a", "c") == ["a", "b", "c"]


def test_floyd_warshall_negative_edge():
    nodes = ["a", "b", "c"]
    edges = [("a", "b", 2), ("b", "c", -1), ("a", "c", 5)]
    dist, _ = floyd_warshall(nodes, edges)
    assert dist["a"]["c"] == 1.0


def test_floyd_warshall_no_path():
    nodes = ["a", "b"]
    dist, nxt = floyd_warshall(nodes, [])
    assert dist["a"]["b"] == float("inf")
    assert reconstruct_path(nxt, "a", "b") is None


def test_floyd_warshall_self():
    nodes = ["a", "b"]
    _, nxt = floyd_warshall(nodes, [])
    assert reconstruct_path(nxt, "a", "a") == ["a"]


def main() -> None:
    test_floyd_warshall_basic()
    test_floyd_warshall_path()
    test_floyd_warshall_negative_edge()
    test_floyd_warshall_no_path()
    test_floyd_warshall_self()
    print("graph_05 (Floyd-Warshall) OK")


if __name__ == "__main__":
    main()
