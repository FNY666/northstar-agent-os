"""graph_21: Stoer-Wagner global minimum cut. Standard library only.

GRAPH_21_VERSION = graph-21.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Tuple

GRAPH_21_VERSION = "graph-21.v1"


def stoer_wagner(weights: Dict[Hashable, Dict[Hashable, float]]) -> Tuple[float, List[Hashable]]:
    """Global min cut of undirected weighted graph. Returns (cut_value, one_side)."""
    verts = list(weights)
    if len(verts) < 2:
        return 0.0, verts
    # work on contracted copies
    w: Dict[Hashable, Dict[Hashable, float]] = {
        u: dict(nbrs) for u, nbrs in weights.items()
    }
    best = float("inf")
    best_side: List[Hashable] = []
    active = list(verts)
    while len(active) > 1:
        in_a = {active[0]}
        order = [active[0]]
        ws = {v: w[active[0]].get(v, 0.0) for v in active if v != active[0]}
        while len(in_a) < len(active):
            # most tightly connected vertex not in A
            nxt = max((v for v in active if v not in in_a), key=lambda v: ws.get(v, 0.0))
            in_a.add(nxt)
            order.append(nxt)
            for v in active:
                if v not in in_a:
                    ws[v] = ws.get(v, 0.0) + w[nxt].get(v, 0.0)
        s, t = order[-2], order[-1]
        cut_val = ws.get(t, 0.0)
        if cut_val < best:
            best = cut_val
            best_side = [v for v in active if v != t]
        # merge t into s
        for v in active:
            if v != s and v != t:
                w[s][v] = w[s].get(v, 0.0) + w[t].get(v, 0.0)
                w[v][s] = w[s][v]
        active.remove(t)
    return best, best_side


def test_stoer_wagner_basic():
    w = {"a": {"b": 3, "c": 3}, "b": {"a": 3, "c": 2, "d": 4},
         "c": {"a": 3, "b": 2, "d": 5}, "d": {"b": 4, "c": 5}}
    cut, _ = stoer_wagner(w)
    assert cut == 6.0  # min cut separates a ({a}) = 3+3


def test_stoer_wagner_two_nodes():
    w = {"a": {"b": 7}, "b": {"a": 7}}
    cut, side = stoer_wagner(w)
    assert cut == 7.0 and len(side) == 1


def test_stoer_wagner_single():
    assert stoer_wagner({"a": {}}) == (0.0, ["a"])


def test_stoer_wagner_complete_k4():
    nodes = ["a", "b", "c", "d"]
    w = {u: {v: 1.0 for v in nodes if v != u} for u in nodes}
    cut, _ = stoer_wagner(w)
    assert cut == 3.0  # isolate one vertex


def test_stoer_wagner_cut_valid():
    w = {"a": {"b": 1}, "b": {"a": 1, "c": 10}, "c": {"b": 10}}
    cut, side = stoer_wagner(w)
    assert cut == 1.0
    assert set(side) in ({"a"}, {"b", "c"})


def main() -> None:
    test_stoer_wagner_basic()
    test_stoer_wagner_two_nodes()
    test_stoer_wagner_single()
    test_stoer_wagner_complete_k4()
    test_stoer_wagner_cut_valid()
    print("graph_21 (Stoer-Wagner) OK")


if __name__ == "__main__":
    main()
