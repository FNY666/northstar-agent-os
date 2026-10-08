"""graph_38: PageRank via power iteration. Standard library only.

GRAPH_38_VERSION = graph-38.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List

GRAPH_38_VERSION = "graph-38.v1"


def pagerank(
    graph: Dict[Hashable, List[Hashable]],
    damping: float = 0.85,
    max_iter: int = 100,
    tol: float = 1e-8,
) -> Dict[Hashable, float]:
    """PageRank; dangling nodes distribute uniformly. Ranks sum to 1."""
    nodes = list(graph)
    n = len(nodes)
    if n == 0:
        return {}
    rank = {u: 1.0 / n for u in nodes}
    out_deg = {u: len(graph.get(u, [])) for u in nodes}
    for _ in range(max_iter):
        new = {u: (1 - damping) / n for u in nodes}
        dangling = sum(rank[u] for u in nodes if out_deg[u] == 0)
        for u in nodes:
            if out_deg[u]:
                share = damping * rank[u] / out_deg[u]
                for v in graph[u]:
                    if v in new:
                        new[v] += share
            # dangling mass spread below
        for u in nodes:
            new[u] += damping * dangling / n
        err = sum(abs(new[u] - rank[u]) for u in nodes)
        rank = new
        if err < tol:
            break
    total = sum(rank.values())
    return {u: r / total for u, r in rank.items()}


def test_pagerank_sums_to_one():
    g = {"a": ["b"], "b": ["c"], "c": ["a"]}
    pr = pagerank(g)
    assert abs(sum(pr.values()) - 1.0) < 1e-9


def test_pagerank_symmetric():
    g = {"a": ["b"], "b": ["a"]}
    pr = pagerank(g)
    assert abs(pr["a"] - pr["b"]) < 1e-9


def test_pagerank_hub_highest():
    # c pointed to by everyone
    g = {"a": ["c"], "b": ["c"], "c": ["a"], "d": ["c"]}
    pr = pagerank(g)
    assert max(pr, key=lambda u: pr[u]) == "c"


def test_pagerank_dangling():
    g = {"a": ["b"], "b": []}
    pr = pagerank(g)
    assert abs(sum(pr.values()) - 1.0) < 1e-9
    assert all(r > 0 for r in pr.values())


def test_pagerank_empty():
    assert pagerank({}) == {}


def main() -> None:
    test_pagerank_sums_to_one()
    test_pagerank_symmetric()
    test_pagerank_hub_highest()
    test_pagerank_dangling()
    test_pagerank_empty()
    print("graph_38 (PageRank) OK")


if __name__ == "__main__":
    main()
