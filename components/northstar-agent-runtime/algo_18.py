"""Iterative depth-first search (DFS).

Explores as far as possible down each branch before backtracking, using an
explicit stack instead of recursion. Neighbors are pushed in reverse order so
the leftmost neighbor is visited first. ``graph`` maps each node to a list of
its neighbors. If ``start`` is not a graph node, the result is empty;
unreachable nodes are simply not visited.

Complexity: time O(V + E), space O(V), where V/E are node/edge counts.
"""

from typing import Dict, Hashable, List

ALGO_18_VERSION = "algo-18.v1"

_STDLIB = frozenset({"typing"})


def dfs(graph: Dict[Hashable, List[Hashable]], start: Hashable) -> List[Hashable]:
    """Return nodes reachable from ``start`` in iterative DFS visit order."""
    order: List[Hashable] = []
    if start not in graph:
        return order
    seen = {start}
    stack = [start]
    while stack:
        node = stack.pop()
        order.append(node)
        for neighbor in reversed(graph.get(node, [])):
            if neighbor not in seen:
                seen.add(neighbor)
                stack.append(neighbor)
    return order


def stdlib_only() -> None:
    """Parse this file with ast; assert all module-level imports are used stdlib."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                imported.setdefault(top, set()).add((alias.asname or top).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                top = node.module.split(".")[0]
                for alias in node.names:
                    imported.setdefault(top, set()).add(alias.asname or alias.name)
    assert set(imported) <= _STDLIB, f"non-stdlib imports: {set(imported) - _STDLIB}"
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for mod, names in imported.items():
        for name in names:
            assert name in used, f"imported but unused: {name} (from {mod})"


def main() -> None:
    g = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": []}
    assert dfs(g, "a") == ["a", "b", "d", "c"]
    assert dfs(g, "d") == ["d"]
    assert dfs(g, "zzz") == []
    g2 = {"a": ["b"], "b": [], "x": ["y"], "y": []}
    assert dfs(g2, "a") == ["a", "b"]
    assert dfs(g2, "x") == ["x", "y"]
    stdlib_only()
    print("algo-18 OK")


if __name__ == "__main__":
    main()
