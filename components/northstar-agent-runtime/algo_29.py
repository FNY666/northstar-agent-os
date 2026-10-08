"""Maximum flow (SIMPLIFIED mock) via Edmonds-Karp.

Repeatedly finds a shortest augmenting path with BFS and pushes the
bottleneck capacity through the residual graph until the sink is
unreachable from the source.

This is a SIMPLIFIED reference implementation: small-input oriented, no
capacity scaling, no min-cost handling, no input validation beyond the
obvious. Time complexity: O(V * E^2). Space: O(V + E).

Returns the maximum flow value (int or float).
"""

from collections import deque
from typing import Dict, Union

ALGO_29_VERSION = "algo-29.v1"

_STDLIB_USED = {"typing", "collections", "ast", "pathlib"}


def max_flow(capacity: Dict, source, sink) -> Union[int, float]:
    """Return the maximum flow value from ``source`` to ``sink``.

    ``capacity`` is dict u -> dict v -> cap (directed capacities; parallel
    edges between the same pair are summed).
    """
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
    return flow


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
        "s": {"a": 10, "b": 10},
        "a": {"b": 2, "t": 10},
        "b": {"t": 10},
        "t": {},
    }
    assert max_flow(cap, "s", "t") == 20, max_flow(cap, "s", "t")
    cap2 = {
        "s": {"a": 3, "b": 2},
        "a": {"b": 1, "t": 3},
        "b": {"t": 2},
        "t": {},
    }
    assert max_flow(cap2, "s", "t") == 5
    assert max_flow({"s": {}, "t": {}}, "s", "t") == 0  # disconnected
    assert max_flow({"s": {"t": 7}}, "s", "t") == 7  # single edge
    assert stdlib_only() is True
    print("algo_29 OK")


if __name__ == "__main__":
    main()
