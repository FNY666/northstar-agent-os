"""graph_39: Betweenness centrality via Brandes' algorithm. Stdlib only.

GRAPH_39_VERSION = graph-39.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List

GRAPH_39_VERSION = "graph-39.v1"


def betweenness_centrality(
    graph: Dict[Hashable, List[Hashable]], normalized: bool = True
) -> Dict[Hashable, float]:
    """Brandes' algorithm for unweighted graphs."""
    nodes = list(graph)
    cb = {u: 0.0 for u in nodes}
    for s in nodes:
        stack: List[Hashable] = []
        pred: Dict[Hashable, List[Hashable]] = {u: [] for u in nodes}
        sigma = {u: 0 for u in nodes}
        sigma[s] = 1
        dist = {u: -1 for u in nodes}
        dist[s] = 0
        q: deque = deque([s])
        while q:
            v = q.popleft()
            stack.append(v)
            for w in graph.get(v, []):
                if w not in dist:
                    continue
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    q.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)
        delta = {u: 0.0 for u in nodes}
        while stack:
            w = stack.pop()
            for v in pred[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                cb[w] += delta[w]
    if normalized and len(nodes) > 2:
        # directed-pair normalization (graph treated as directed)
        scale = 1.0 / ((len(nodes) - 1) * (len(nodes) - 2))
        cb = {u: c * scale for u, c in cb.items()}
    return cb


def test_betweenness_path_middle():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    cb = betweenness_centrality(g, normalized=False)
    assert cb["b"] == 2.0 and cb["a"] == 0.0


def test_betweenness_star():
    g = {"c": ["a", "b", "d"], "a": ["c"], "b": ["c"], "d": ["c"]}
    cb = betweenness_centrality(g, normalized=False)
    assert cb["c"] == 6.0
    assert all(cb[u] == 0.0 for u in ("a", "b", "d"))


def test_betweenness_normalized_range():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c"]}
    cb = betweenness_centrality(g, normalized=True)
    assert all(0.0 <= v <= 1.0 for v in cb.values())


def test_betweenness_disconnected():
    g = {"a": ["b"], "b": ["a"], "c": ["d"], "d": ["c"]}
    cb = betweenness_centrality(g)
    assert all(v >= 0 for v in cb.values())


def test_betweenness_single():
    assert betweenness_centrality({"a": []}) == {"a": 0.0}


def main() -> None:
    test_betweenness_path_middle()
    test_betweenness_star()
    test_betweenness_normalized_range()
    test_betweenness_disconnected()
    test_betweenness_single()
    print("graph_39 (betweenness) OK")


if __name__ == "__main__":
    main()
