"""level_order: level-order traversal of a binary tree given as nested (val, left, right) tuples. IS: a list of per-level value lists; None root yields []. IS NOT: a recursive DFS or an iterator-based traversal."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, List, Optional, Tuple
VERSION = "queue-12.v1"

_Tree = Optional[Tuple[Any, object, object]]


def _req_tree(node: object, depth: int = 0) -> _Tree:
    if depth > 1000:
        raise ValueError("tree too deep")
    if node is None:
        return None
    if not isinstance(node, tuple) or len(node) != 3:
        raise ValueError("node must be None or a (value, left, right) tuple")
    return (node[0], _req_tree(node[1], depth + 1), _req_tree(node[2], depth + 1))


def level_order(root: object) -> List[List[Any]]:
    """Return values grouped by depth, left to right."""
    root = _req_tree(root)
    if root is None:
        return []
    q: deque = deque([root])
    levels: List[List[Any]] = []
    while q:
        level: List[Any] = []
        for _ in range(len(q)):
            val, left, right = q.popleft()
            level.append(val)
            if left is not None:
                q.append(left)
            if right is not None:
                q.append(right)
        levels.append(level)
    return levels


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    t = (1, (2, (4, None, None), (5, None, None)), (3, None, None))
    assert level_order(t) == [[1], [2, 3], [4, 5]]
    assert level_order(None) == []
    assert level_order((9, None, None)) == [[9]]
    try:
        level_order((1, 2, 3))
    except ValueError:
        pass
    else:
        raise AssertionError("malformed node must raise ValueError")
    try:
        level_order("tree")
    except ValueError:
        pass
    else:
        raise AssertionError("non-tuple root must raise ValueError")
    assert stdlib_only()
    print("queue-12 OK: level-order traversal")


if __name__ == "__main__":
    main()
