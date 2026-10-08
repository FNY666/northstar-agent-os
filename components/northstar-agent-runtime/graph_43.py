"""graph_43: 2-approximation vertex cover (maximal matching). Stdlib only.

GRAPH_43_VERSION = graph-43.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Set, Tuple

GRAPH_43_VERSION = "graph-43.v1"


def _edges(graph: Dict[Hashable, List[Hashable]]) -> List[Tuple[Hashable, Hashable]]:
    seen = set()
    out = []
    for u, nbrs in graph.items():
        for v in nbrs:
            if (repr(v), repr(u)) not in seen:
                seen.add((repr(u), repr(v)))
                out.append((u, v))
    return out


def approx_vertex_cover(graph: Dict[Hashable, List[Hashable]]) -> List[Hashable]:
    """2-approx: take both endpoints of a maximal matching."""
    cover: Set[Hashable] = set()
    for u, v in _edges(graph):
        if u not in cover and v not in cover:
            cover.add(u)
            cover.add(v)
    return sorted(cover, key=repr)


def is_vertex_cover(graph: Dict[Hashable, List[Hashable]], cover: List[Hashable]) -> bool:
    s = set(cover)
    return all(u in s or v in s for u, v in _edges(graph))


def test_vc_path():
    g = {"a": ["b"], "b": ["a", "c"], "c": ["b"]}
    c = approx_vertex_cover(g)
    assert is_vertex_cover(g, c) and len(c) <= 2


def test_vc_triangle():
    g = {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}
    c = approx_vertex_cover(g)
    assert is_vertex_cover(g, c) and len(c) <= 2 * 2  # 2-approx of opt=2


def test_vc_star():
    g = {"c": ["a", "b", "d"], "a": ["c"], "b": ["c"], "d": ["c"]}
    c = approx_vertex_cover(g)
    assert is_vertex_cover(g, c)


def test_vc_empty():
    assert approx_vertex_cover({"a": []}) == []


def test_vc_complete_k4():
    nodes = ["a", "b", "c", "d"]
    g = {u: [v for v in nodes if v != u] for u in nodes}
    c = approx_vertex_cover(g)
    assert is_vertex_cover(g, c) and len(c) <= 2 * 3


def main() -> None:
    test_vc_path()
    test_vc_triangle()
    test_vc_star()
    test_vc_empty()
    test_vc_complete_k4()
    print("graph_43 (vertex cover) OK")


if __name__ == "__main__":
    main()
