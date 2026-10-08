"""Lowest common ancestor (simplified) from a parent-pointer map.

simplified: lca(parent, u, v) works on a dict mapping each node to its
parent (the root maps to None). It collects u's ancestors into a set
and walks up from v until it hits one of them. No binary lifting, no
preprocessing -- O(depth) time, O(depth) space per query.

Returns the lowest common ancestor of u and v, or None if u or v is
not in the tree (or if they belong to different trees).
"""

from __future__ import annotations

import ast
import sys
from typing import Any, Dict, Hashable, Optional, Set

ALGO_40_VERSION = "algo-40.v1"


def lca(
    parent: Dict[Hashable, Optional[Hashable]],
    u: Hashable,
    v: Hashable,
) -> Optional[Hashable]:
    """Return the lowest common ancestor of u and v, or None."""
    if u not in parent or v not in parent:
        return None
    ancestors: Set[Hashable] = set()
    node: Optional[Hashable] = u
    while node is not None:
        ancestors.add(node)
        node = parent[node]
    node = v
    while node is not None:
        if node in ancestors:
            return node
        node = parent[node]
    return None


def stdlib_only() -> bool:
    """Assert every imported top-level module is from the stdlib."""
    src = open(__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in stdlib, node.module
    return True


def main() -> None:
    #        1
    #      /   \
    #     2     3
    #    / \     \
    #   4   5     6
    parent = {1: None, 2: 1, 3: 1, 4: 2, 5: 2, 6: 3}
    assert lca(parent, 4, 5) == 2
    assert lca(parent, 4, 6) == 1
    assert lca(parent, 4, 2) == 2   # ancestor of the other
    assert lca(parent, 1, 6) == 1
    assert lca(parent, 3, 3) == 3   # same node
    assert lca(parent, 4, 99) is None  # unknown node
    assert lca(parent, 99, 4) is None
    # Disjoint trees share no ancestor.
    parent2 = {1: None, 2: 1, 7: None, 8: 7}
    assert lca(parent2, 2, 8) is None
    # Single-node tree.
    assert lca({1: None}, 1, 1) == 1
    # Empty map.
    assert lca({}, 1, 2) is None
    assert stdlib_only()
    print("algo_40 OK")


if __name__ == "__main__":
    main()
