"""graph_17: Hopcroft-Karp maximum bipartite matching. Standard library only.

GRAPH_17_VERSION = graph-17.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List, Set, Tuple

GRAPH_17_VERSION = "graph-17.v1"


def hopcroft_karp(
    adj: Dict[Hashable, List[Hashable]], left: List[Hashable]
) -> Tuple[Dict[Hashable, Hashable], int]:
    """Maximum bipartite matching. Returns (match_left_to_right, size)."""
    INF = float("inf")
    pair_u: Dict[Hashable, Hashable] = {}
    pair_v: Dict[Hashable, Hashable] = {}
    dist: Dict[Hashable, float] = {}

    def bfs() -> bool:
        q: deque = deque()
        for u in left:
            if u not in pair_u:
                dist[u] = 0
                q.append(u)
            else:
                dist[u] = INF
        dist[None] = INF  # type: ignore[index]
        while q:
            u = q.popleft()
            if dist[u] < dist[None]:  # type: ignore[index]
                for v in adj.get(u, []):
                    pu = pair_v.get(v)
                    if dist.get(pu, INF) == INF:
                        dist[pu] = dist[u] + 1  # type: ignore[index]
                        q.append(pu)
        return dist[None] != INF  # type: ignore[index]

    def dfs(u: Hashable) -> bool:
        if u is None:
            return True
        for v in adj.get(u, []):
            pu = pair_v.get(v)
            if dist.get(pu, INF) == dist[u] + 1 and dfs(pu):
                pair_u[u] = v
                pair_v[v] = u
                return True
        dist[u] = INF
        return False

    matching = 0
    while bfs():
        for u in left:
            if u not in pair_u and dfs(u):
                matching += 1
    return pair_u, matching


def test_hopcroft_karp_basic():
    adj = {"l1": ["r1", "r2"], "l2": ["r1"], "l3": ["r2", "r3"]}
    match, size = hopcroft_karp(adj, ["l1", "l2", "l3"])
    assert size == 3
    assert len(set(match.values())) == 3


def test_hopcroft_karp_partial():
    adj = {"l1": ["r1"], "l2": ["r1"]}
    _, size = hopcroft_karp(adj, ["l1", "l2"])
    assert size == 1


def test_hopcroft_karp_empty():
    _, size = hopcroft_karp({}, [])
    assert size == 0


def test_hopcroft_karp_complete():
    left = [f"l{i}" for i in range(4)]
    adj = {u: [f"r{j}" for j in range(4)] for u in left}
    _, size = hopcroft_karp(adj, left)
    assert size == 4


def test_hopcroft_karp_match_valid():
    adj = {"a": ["x", "y"], "b": ["y", "z"], "c": ["x"]}
    match, size = hopcroft_karp(adj, ["a", "b", "c"])
    for u, v in match.items():
        assert v in adj[u]
    assert size == len(match)


def main() -> None:
    test_hopcroft_karp_basic()
    test_hopcroft_karp_partial()
    test_hopcroft_karp_empty()
    test_hopcroft_karp_complete()
    test_hopcroft_karp_match_valid()
    print("graph_17 (Hopcroft-Karp) OK")


if __name__ == "__main__":
    main()
