"""graph_40: Closeness centrality (BFS-based). Standard library only.

GRAPH_40_VERSION = graph-40.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable

GRAPH_40_VERSION = "graph-40.v1"


def closeness_centrality(graph: Dict[Hashable, list]) -> Dict[Hashable, float]:
    """Closeness = (reachable-1) / sum(distances); 0 if isolated."""
    result: Dict[Hashable, float] = {}
    for s in graph:
        dist = {s: 0}
        q: deque = deque([s])
        while q:
            u = q.popleft()
            for v in graph.get(u, []):
                if v not in dist:
                    dist[v] = dist[u] + 1
                    q.append(v)
        total = sum(dist.values())
        reachable = len(dist)
        result[s] = (reachable - 1) / total if total > 0 else 0.0
    return result


def test_closeness_path():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    cc = closeness_centrality(g)
    assert cc["b"] > cc["a"] and cc["b"] > cc["c"]


def test_closeness_star():
    g = {"c": ["a", "b", "d"], "a": ["c"], "b": ["c"], "d": ["c"]}
    cc = closeness_centrality(g)
    assert cc["c"] == max(cc.values())


def test_closeness_isolated():
    assert closeness_centrality({"a": []}) == {"a": 0.0}


def test_closeness_complete():
    nodes = ["a", "b", "c"]
    g = {u: [v for v in nodes if v != u] for u in nodes}
    cc = closeness_centrality(g)
    assert all(v == 1.0 for v in cc.values())


def test_closeness_range():
    g = {"a": ["b", "c"], "b": ["a"], "c": ["a", "d"], "d": ["c"]}
    cc = closeness_centrality(g)
    assert all(0.0 <= v <= 1.0 for v in cc.values())


def main() -> None:
    test_closeness_path()
    test_closeness_star()
    test_closeness_isolated()
    test_closeness_complete()
    test_closeness_range()
    print("graph_40 (closeness) OK")


if __name__ == "__main__":
    main()
