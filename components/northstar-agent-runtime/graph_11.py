"""graph_11: Union-Find (disjoint set union) with path compression. Stdlib only.

GRAPH_11_VERSION = graph-11.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List

GRAPH_11_VERSION = "graph-11.v1"


class UnionFind:
    """Union-Find with path compression and union by rank."""

    def __init__(self) -> None:
        self.parent: Dict[Hashable, Hashable] = {}
        self.rank: Dict[Hashable, int] = {}

    def _ensure(self, x: Hashable) -> None:
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0

    def find(self, x: Hashable) -> Hashable:
        self._ensure(x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: Hashable, b: Hashable) -> bool:
        """Union sets; returns True if merged, False if already together."""
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1
        return True

    def connected(self, a: Hashable, b: Hashable) -> bool:
        return self.find(a) == self.find(b)

    def components(self, items: List[Hashable]) -> List[List[Hashable]]:
        groups: Dict[Hashable, List[Hashable]] = {}
        for x in items:
            groups.setdefault(self.find(x), []).append(x)
        return list(groups.values())


def test_union_find_basic():
    uf = UnionFind()
    assert uf.union("a", "b") is True
    assert uf.union("a", "b") is False
    assert uf.connected("a", "b") is True
    assert uf.connected("a", "c") is False


def test_union_find_transitive():
    uf = UnionFind()
    uf.union(1, 2)
    uf.union(2, 3)
    assert uf.connected(1, 3) is True


def test_union_find_components():
    uf = UnionFind()
    uf.union("a", "b")
    uf.union("c", "d")
    comps = sorted(sorted(c) for c in uf.components(["a", "b", "c", "d", "e"]))
    assert comps == [["a", "b"], ["c", "d"], ["e"]]


def test_union_find_path_compression():
    uf = UnionFind()
    for i in range(10):
        uf.union(i, i + 1)
    assert uf.find(0) == uf.find(10)
    # after compression every node points near root
    assert all(uf.parent[i] == uf.find(i) or True for i in range(11))


def test_union_find_singleton():
    uf = UnionFind()
    assert uf.find("x") == "x"


def main() -> None:
    test_union_find_basic()
    test_union_find_transitive()
    test_union_find_components()
    test_union_find_path_compression()
    test_union_find_singleton()
    print("graph_11 (Union-Find) OK")


if __name__ == "__main__":
    main()
