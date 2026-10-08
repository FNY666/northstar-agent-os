"""greedy_41: Kruskal minimum spanning tree.

Add edges in increasing weight order, skipping those that close a cycle (union-find).

Time complexity: O(E log E) time
Space complexity: O(V) auxiliary
"""

import ast
import sys
GREEDY_41_VERSION = "greedy-41.v1"


def kruskal_mst_weight(n, edges):
    """Return the MST weight for n nodes labeled 0..n-1.

    edges: iterable of (u, v, w).
    """
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    total = 0
    for u, v, w in sorted(edges, key=lambda e: e[2]):
        ru, rv = find(u), find(v)
        if ru != rv:
            parent[ru] = rv
            total += w
    return total

def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True



def main() -> None:
    assert kruskal_mst_weight(4, [(0, 1, 10), (0, 2, 6), (0, 3, 5), (1, 3, 15), (2, 3, 4)]) == 19
    assert kruskal_mst_weight(1, []) == 0
    assert kruskal_mst_weight(3, [(0, 1, 1), (1, 2, 2), (0, 2, 3)]) == 3
    assert kruskal_mst_weight(2, [(0, 1, 7)]) == 7
    assert stdlib_only()
    print("greedy_41 OK")


if __name__ == "__main__":
    main()
