"""Topological sort via Kahn's algorithm.

Given a directed acyclic graph as ``dict`` node -> list of neighbors,
returns a linear ordering of the nodes such that for every edge u -> v,
u appears before v.

Time complexity: O(V + E). Space complexity: O(V + E).
Raises ValueError if the graph contains a cycle.
"""

from typing import Dict, List

ALGO_21_VERSION = "algo-21.v1"

_STDLIB_USED = {"typing", "ast", "pathlib"}


def topological_sort(graph: Dict) -> List:
    """Return a topological ordering of ``graph`` (Kahn's algorithm).

    Nodes that appear only as neighbors (never as keys) are included.
    Raises ValueError if a cycle is detected.
    """
    indegree = {node: 0 for node in graph}
    for node, neighbors in graph.items():
        for nb in neighbors:
            indegree[nb] = indegree.get(nb, 0) + 1
    queue = [n for n, d in indegree.items() if d == 0]
    order = []
    while queue:
        node = queue.pop(0)
        order.append(node)
        for nb in graph.get(node, []):
            indegree[nb] -= 1
            if indegree[nb] == 0:
                queue.append(nb)
    if len(order) != len(indegree):
        raise ValueError("graph contains a cycle; no topological ordering exists")
    return order


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
    order = topological_sort({"A": ["B", "C"], "B": ["D"], "C": ["D"], "D": []})
    assert order == ["A", "B", "C", "D"], order
    assert topological_sort({}) == []
    assert topological_sort({"solo": []}) == ["solo"]
    assert topological_sort({"A": ["B"], "B": [], "C": []}) == ["A", "C", "B"]
    try:
        topological_sort({"A": ["B"], "B": ["C"], "C": ["A"]})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError on cycle")
    assert stdlib_only() is True
    print("algo_21 OK")


if __name__ == "__main__":
    main()
