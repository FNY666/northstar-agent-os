"""graph_16: Dinic's maximum flow (level graph + blocking flow). Stdlib only.

GRAPH_16_VERSION = graph-16.v1
"""
from __future__ import annotations

from collections import deque
from typing import Dict, Hashable, List, Tuple

GRAPH_16_VERSION = "graph-16.v1"


class _Edge:
    __slots__ = ("to", "rev", "cap")

    def __init__(self, to: Hashable, rev: int, cap: float) -> None:
        self.to = to
        self.rev = rev
        self.cap = cap


class Dinic:
    def __init__(self) -> None:
        self.g: Dict[Hashable, List[_Edge]] = {}

    def add_edge(self, u: Hashable, v: Hashable, cap: float) -> None:
        self.g.setdefault(u, [])
        self.g.setdefault(v, [])
        self.g[u].append(_Edge(v, len(self.g[v]), cap))
        self.g[v].append(_Edge(u, len(self.g[u]) - 1, 0.0))

    def max_flow(self, s: Hashable, t: Hashable) -> float:
        total = 0.0
        INF = float("inf")
        while True:
            level = {s: 0}
            q: deque = deque([s])
            while q:
                u = q.popleft()
                for e in self.g.get(u, []):
                    if e.cap > 0 and e.to not in level:
                        level[e.to] = level[u] + 1
                        q.append(e.to)
            if t not in level:
                break
            it = {u: 0 for u in self.g}

            def dfs(u: Hashable, f: float) -> float:
                if u == t:
                    return f
                i = it[u]
                while i < len(self.g[u]):
                    e = self.g[u][i]
                    if e.cap > 0 and level.get(e.to, -1) == level[u] + 1:
                        ret = dfs(e.to, min(f, e.cap))
                        if ret > 0:
                            e.cap -= ret
                            self.g[e.to][e.rev].cap += ret
                            return ret
                    i += 1
                    it[u] = i
                return 0.0

            while True:
                pushed = dfs(s, INF)
                if pushed == 0:
                    break
                total += pushed
        return total


def test_dinic_classic():
    d = Dinic()
    for u, v, c in [
        ("s", "a", 10), ("s", "b", 10), ("a", "b", 2), ("a", "c", 4),
        ("a", "d", 8), ("b", "d", 9), ("c", "t", 10), ("d", "c", 6), ("d", "t", 10),
    ]:
        d.add_edge(u, v, c)
    assert d.max_flow("s", "t") == 19.0


def test_dinic_simple():
    d = Dinic()
    d.add_edge("s", "t", 7)
    assert d.max_flow("s", "t") == 7.0


def test_dinic_disconnected():
    d = Dinic()
    d.add_edge("s", "a", 5)
    assert d.max_flow("s", "t") == 0.0


def test_dinic_parallel_paths():
    d = Dinic()
    d.add_edge("s", "a", 5)
    d.add_edge("s", "b", 5)
    d.add_edge("a", "t", 5)
    d.add_edge("b", "t", 5)
    assert d.max_flow("s", "t") == 10.0


def test_dinic_second_network():
    # hand-computed: s->a 3, s->b 3, a->t 3, b->t 3, a->b 1 => 6
    d = Dinic()
    for u, v, c in [("s", "a", 3), ("s", "b", 3), ("a", "t", 3), ("b", "t", 3), ("a", "b", 1)]:
        d.add_edge(u, v, c)
    assert d.max_flow("s", "t") == 6.0


def main() -> None:
    test_dinic_classic()
    test_dinic_simple()
    test_dinic_disconnected()
    test_dinic_parallel_paths()
    test_dinic_second_network()
    print("graph_16 (Dinic) OK")


if __name__ == "__main__":
    main()
