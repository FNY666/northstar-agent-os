"""zigzag_level_order: zigzag (spiral) level-order traversal alternating direction per level. IS: a zigzag level list; None root yields []. IS NOT: a plain level-order or a column-wise traversal."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, List, Optional, Tuple
VERSION = "queue-13.v1"

def _req_tree(node: object, depth: int = 0):  # type: ignore[no-untyped-def]
    if depth > 1000:
        raise ValueError("tree too deep")
    if node is None:
        return None
    if not isinstance(node, tuple) or len(node) != 3:
        raise ValueError("node must be None or a (value, left, right) tuple")
    return (node[0], _req_tree(node[1], depth + 1), _req_tree(node[2], depth + 1))


def zigzag_level_order(root: object) -> List[List[Any]]:
    """Return per-level values, direction alternating left-to-right/right-to-left."""
    root = _req_tree(root)
    if root is None:
        return []
    q: deque = deque([root])
    levels: List[List[Any]] = []
    left_to_right = True
    while q:
        level: List[Any] = []
        for _ in range(len(q)):
            val, left, right = q.popleft()
            level.append(val)
            if left is not None:
                q.append(left)
            if right is not None:
                q.append(right)
        levels.append(level if left_to_right else level[::-1])
        left_to_right = not left_to_right
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
    t = (1, (2, (4, None, None), (5, None, None)), (3, (6, None, None), (7, None, None)))
    assert zigzag_level_order(t) == [[1], [3, 2], [4, 5, 6, 7]]
    assert zigzag_level_order(None) == []
    assert zigzag_level_order((9, None, None)) == [[9]]
    try:
        zigzag_level_order([1, 2, 3])
    except ValueError:
        pass
    else:
        raise AssertionError("malformed tree must raise ValueError")
    assert stdlib_only()
    print("queue-13 OK: zigzag traversal")


if __name__ == "__main__":
    main()
