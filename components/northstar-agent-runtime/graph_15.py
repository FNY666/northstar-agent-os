"""graph_15: Edmonds-Karp maximum flow. Standard library only.

GRAPH_15_VERSION = graph-15.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List, Optional, Tuple

GRAPH_15_VERSION = "graph-15.v1"


def edmonds_karp(
    capacity: Dict[Hashable, Dict[Hashable, float]], source: Hashable, sink: Hashable
) -> Tuple[float, Dict[Hashable, Dict[Hashable, float]]]:
    """Max flow via BFS augmenting paths. Returns (flow_value, flow_dict)."""
    nodes = set(capacity)
    for nbrs in capacity.values():
        nodes.update(nbrs)
    flow: Dict[Hashable, Dict[Hashable, float]] = {u: {} for u in nodes}

    def residual(u: Hashable, v: Hashable) -> float:
        return capacity.get(u, {}).get(v, 0.0) - flow[u].get(v, 0.0)

    def bfs_parent() -> Optional[Dict[Hashable, Hashable]]:
        parent: Dict[Hashable, Hashable] = {}
        q: deque = deque([source])
        parent[source] = source  # type: ignore[assignment]
        while q:
            u = q.popleft()
            for v in nodes:
                if v not in parent and residual(u, v) > 0:
                    parent[v] = u
                    if v == sink:
                        return parent
                    q.append(v)
        return None

    total = 0.0
    while True:
        parent = bfs_parent()
        if parent is None or sink not in parent:
            break
        bottleneck = float("inf")
        v = sink
        while v != source:
            u = parent[v]
            bottleneck = min(bottleneck, residual(u, v))
            v = u
        v = sink
        while v != source:
            u = parent[v]
            flow[u][v] = flow[u].get(v, 0.0) + bottleneck
            flow[v][u] = flow[v].get(u, 0.0) - bottleneck
            v = u
        total += bottleneck
    return total, flow


def test_edmonds_karp_classic():
    cap = {
        "s": {"a": 10, "b": 10},
        "a": {"b": 2, "c": 4, "d": 8},
        "b": {"d": 9},
        "c": {"t": 10},
        "d": {"c": 6, "t": 10},
        "t": {},
    }
    total, _ = edmonds_karp(cap, "s", "t")
    assert total == 19.0


def test_edmonds_karp_simple():
    cap = {"s": {"t": 5}, "t": {}}
    total, _ = edmonds_karp(cap, "s", "t")
    assert total == 5.0


def test_edmonds_karp_disconnected():
    cap = {"s": {"a": 3}, "a": {}, "t": {}}
    total, _ = edmonds_karp(cap, "s", "t")
    assert total == 0.0


def test_edmonds_karp_flow_conservation():
    cap = {"s": {"a": 10, "b": 10}, "a": {"t": 10}, "b": {"t": 10}, "t": {}}
    total, flow = edmonds_karp(cap, "s", "t")
    assert total == 20.0
    # conservation at 'a': in == out
    inflow = sum(flow[u].get("a", 0.0) for u in flow if flow[u].get("a", 0.0) > 0)
    outflow = sum(v for v in flow["a"].values() if v > 0)
    assert abs(inflow - outflow) < 1e-9


def test_edmonds_karp_bottleneck():
    cap = {"s": {"a": 100}, "a": {"b": 3}, "b": {"t": 100}, "t": {}}
    total, _ = edmonds_karp(cap, "s", "t")
    assert total == 3.0


def main() -> None:
    test_edmonds_karp_classic()
    test_edmonds_karp_simple()
    test_edmonds_karp_disconnected()
    test_edmonds_karp_flow_conservation()
    test_edmonds_karp_bottleneck()
    print("graph_15 (Edmonds-Karp) OK")


if __name__ == "__main__":
    main()
