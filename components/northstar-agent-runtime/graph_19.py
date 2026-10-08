"""graph_19: Bipartite matching via Kuhn's augmenting-path (DFS). Stdlib only.

GRAPH_19_VERSION = graph-19.v1
"""
from __future__ import annotations

from typing import Dict, Hashable, List, Set, Tuple

GRAPH_19_VERSION = "graph-19.v1"


def kuhn_matching(
    adj: Dict[Hashable, List[Hashable]], left: List[Hashable]
) -> Tuple[Dict[Hashable, Hashable], int]:
    """Kuhn's algorithm. Returns (match_left_to_right, size)."""
    match_r: Dict[Hashable, Hashable] = {}

    def try_kuhn(u: Hashable, seen: Set[Hashable]) -> bool:
        for v in adj.get(u, []):
            if v in seen:
                continue
            seen.add(v)
            if v not in match_r or try_kuhn(match_r[v], seen):
                match_r[v] = u
                return True
        return False

    size = 0
    for u in left:
        if try_kuhn(u, set()):
            size += 1
    match_l = {u: v for v, u in match_r.items()}
    return match_l, size


def minimum_vertex_cover_bipartite(
    adj: Dict[Hashable, List[Hashable]], left: List[Hashable]
) -> Tuple[List[Hashable], List[Hashable]]:
    """Konig's theorem: min vertex cover from max matching."""
    match_l, _ = kuhn_matching(adj, left)
    match_r = {v: u for u, v in match_l.items()}
    # vertices reachable from free left vertices via alternating paths
    free = [u for u in left if u not in match_l]
    seen_l: Set[Hashable] = set()
    seen_r: Set[Hashable] = set()
    stack = list(free)
    while stack:
        u = stack.pop()
        if u in seen_l:
            continue
        seen_l.add(u)
        for v in adj.get(u, []):
            if v not in match_l.get(u, object()) and v not in seen_r:
                seen_r.add(v)
                if v in match_r and match_r[v] not in seen_l:
                    stack.append(match_r[v])
    cover_l = [u for u in left if u not in seen_l]
    right = sorted({v for nbrs in adj.values() for v in nbrs})
    cover_r = [v for v in right if v in seen_r]
    return cover_l, cover_r


def test_kuhn_basic():
    adj = {"l1": ["r1", "r2"], "l2": ["r1"], "l3": ["r2", "r3"]}
    _, size = kuhn_matching(adj, ["l1", "l2", "l3"])
    assert size == 3


def test_kuhn_partial():
    adj = {"l1": ["r1"], "l2": ["r1"]}
    _, size = kuhn_matching(adj, ["l1", "l2"])
    assert size == 1


def test_kuhn_hand_computed():
    # only 3 right vertices => max matching is 3
    adj = {"a": ["x", "y"], "b": ["y"], "c": ["x", "z"], "d": ["z"]}
    match, size = kuhn_matching(adj, ["a", "b", "c", "d"])
    assert size == 3
    assert len(set(match.values())) == 3


def test_konig_cover_size():
    adj = {"l1": ["r1", "r2"], "l2": ["r1"], "l3": ["r2", "r3"]}
    left = ["l1", "l2", "l3"]
    cl, cr = minimum_vertex_cover_bipartite(adj, left)
    _, msize = kuhn_matching(adj, left)
    assert len(cl) + len(cr) == msize  # Konig: |cover| == |matching|


def test_kuhn_empty():
    assert kuhn_matching({}, []) == ({}, 0)


def main() -> None:
    test_kuhn_basic()
    test_kuhn_partial()
    test_kuhn_hand_computed()
    test_konig_cover_size()
    test_kuhn_empty()
    print("graph_19 (Kuhn matching) OK")


if __name__ == "__main__":
    main()
