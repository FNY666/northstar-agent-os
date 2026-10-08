"""Minimum cut (SIMPLIFIED mock) via the max-flow min-cut theorem.

Runs Edmonds-Karp max flow internally, then takes the set of nodes
reachable from the source in the final residual graph. That set is the
source side of a minimum s-t cut; the cut value equals the max flow value.

This is a SIMPLIFIED reference implementation: small-input oriented, no
capacity scaling, no enumeration of all minimum cuts.
Time complexity: O(V * E^2). Space: O(V + E).

Returns (cut_value, reachable_set).
"""

from collections import deque
from typing import Dict, Set, Tuple, Union

ALGO_30_VERSION = "algo-30.v1"

_STDLIB_USED = {"typing", "collections", "ast", "pathlib"}


def _residual_after_max_flow(capacity: Dict, source, sink) -> Tuple[Dict, Union[int, float]]:
    residual: Dict = {}
    for u, nbrs in capacity.items():
        for v, c in nbrs.items():
            residual.setdefault(u, {})[v] = residual.setdefault(u, {}).get(v, 0) + c
            residual.setdefault(v, {})

    flow: Union[int, float] = 0
    while True:
        parent = {source: None}
        queue = deque([source])
        while queue and sink not in parent:
            u = queue.popleft()
            for v, c in residual.get(u, {}).items():
                if c > 0 and v not in parent:
                    parent[v] = u
                    queue.append(v)
        if sink not in parent:
            break
        bottleneck = float("inf")
        v = sink
        while v != source:
            u = parent[v]
            bottleneck = min(bottleneck, residual[u][v])
            v = u
        v = sink
        while v != source:
            u = parent[v]
            residual[u][v] -= bottleneck
            residual[v][u] = residual[v].get(u, 0) + bottleneck
            v = u
        flow += bottleneck
    return residual, flow


def min_cut(capacity: Dict, source, sink) -> Tuple[Union[int, float], Set]:
    """Return (cut_value, reachable_set) for the minimum s-t cut.

    ``reachable_set`` is the set of nodes reachable from ``source`` in the
    residual graph after max flow (the source side of the cut).
    """
    residual, flow = _residual_after_max_flow(capacity, source, sink)
    reachable = {source}
    queue = deque([source])
    while queue:
        u = queue.popleft()
        for v, c in residual.get(u, {}).items():
            if c > 0 and v not in reachable:
                reachable.add(v)
                queue.append(v)
    return flow, reachable


def stdlib_only() -> bool:
    """Assert every imported top-level module is one actually used from the stdlib."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= _STDLIB_USED, f"non-stdlib/unused import: {imported - _STDLIB_USED}"
    return True


def main() -> None:
    cap = {
        "s": {"a": 5, "b": 5},
        "a": {"t": 3},
        "b": {"t": 7},
        "t": {},
    }
    value, reach = min_cut(cap, "s", "t")
    assert value == 8, value
    assert reach == {"s", "a"}, reach
    value2, reach2 = min_cut({"s": {}, "t": {}}, "s", "t")
    assert value2 == 0 and reach2 == {"s"}
    value3, reach3 = min_cut({"s": {"t": 7}}, "s", "t")
    assert value3 == 7 and reach3 == {"s"}
    # min-cut value must equal the max-flow value (max-flow min-cut theorem)
    cap4 = {
        "s": {"a": 10, "b": 10},
        "a": {"b": 2, "t": 10},
        "b": {"t": 10},
        "t": {},
    }
    value4, reach4 = min_cut(cap4, "s", "t")
    assert value4 == 20 and "t" not in reach4
    assert stdlib_only() is True
    print("algo_30 OK")


if __name__ == "__main__":
    main()
